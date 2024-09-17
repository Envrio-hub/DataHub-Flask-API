__version__="1.1.0"
__authors__=['Ioannis Tsakmakis']
__date_created__='2023-11-21'
__last_updated__='2024-09-17'

from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_cors import CORS
from datetime import datetime, timedelta
import pandas as pd
from databases_utils import crud, influx
import boto3, json
from cognito import CognitoIdentityProviderWrapper, DecodeVerifyJWT
from datetime import datetime

app = Flask(__name__)
CORS(app)

api = Api(app)

prefix = 'api'
class Authentication(Resource):

    def post(self):
        data = request.get_json()

        if crud.User.get_by_email(email=data['username']):

            with open('cognito.json','r') as f:
                cognito = json.load(f)

            client = boto3.client('cognito-idp',region_name=cognito['region'],
                                aws_access_key_id=cognito['access_key_id'], aws_secret_access_key=cognito['secret_access_key'])
            
            cognito = CognitoIdentityProviderWrapper(cognito_idp_client=client, user_pool_id=cognito['user_pool_id'],
                                                    client_id=cognito['client_id'], client_secret=cognito['client_secret'])
            
            response = cognito.start_sign_in(user_name=data['username'], password=data['password'])
        
            if response.get('AuthenticationResult'):
                subscription_status = crud.User.get_by_email(email=data['username']).Users.subscription_expires_in
                if subscription_status == -9:
                    return {'message':'succefull authentication','access_token':response['AuthenticationResult']['AccessToken']}
                else:
                    response = {'message':'Unauthorized','errors':['Your subscription has expired']} if datetime.strptime(subscription_status,"%Y-%m-%d") < datetime.now() else {'message':'succefull authendication','access_token':response['AuthenticationResult']['AccessToken']}
                    return response
            else:
                return {'message':response['code'],'errors':[response['message']]}, 401
            
        else:
            return {'message':'Account does not exist','errors':['The provided username is not registered. Check spelling or contact our support at support@envrio.org']}, 404
            

class GetStations(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","errors": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token})
        if claims.get('message'):
            return claims, 401
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        stations = crud.Stations.get_by_access(user_id=get_user_id(claims['sub']).Users.id)
        response = [{"station_id":station.Stations.id,"date_created":datetime.fromtimestamp(station.Stations.date_created).strftime('%Y-%m-%d %H:%M'),
                     "last_communication":datetime.fromtimestamp(station.Stations.last_communication).strftime('%Y-%m-%d %H:%M'),"longitude":float(station.Stations.longitude),
                     "latitude":float(station.Stations.latitude),"elevation":station.Stations.elevation,"name":station.Stations.name['en']} for station in stations]
        return response
    
class GetStationData(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","errors": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token})
        if claims.get('message'):
            return claims, 401
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        args = request.args
        start = (datetime.now() - timedelta(days = 3))
        end =  datetime.now()
        stations = [station.Stations.id for station in crud.Stations.get_by_access(user_id=get_user_id(claims['sub']).Users.id)]
        if not args['station_id'] in stations:
            return {"message": "Forbidden", 'errors':["You do not have permission to access this station."]}, 403
        sensors_info = crud.MonitoredParameters.get_by_station_id(station_id=int(args['station_id']))
        sensors_info = [{'sensor_id':sensor.MonitoredParameters.id,'measurement':sensor.MonitoredParameters.measurement,
                         'unit':sensor.MonitoredParameters.unit} for sensor in sensors_info]
        flux = influx.DataManagement(bucket_name='sensors_meters', organization='envrio', conf_file='C:/Users/xylop/Documents/github_repos/.certification_files/envrio_config.ini')
        station_data = {}
        for sensor in sensors_info:
            data = flux.query_data(measurement=sensor['measurement'], sensor_id=sensor['sensor_id'], unit=sensor['unit'],
                                   start=start, stop=end)
            data_dict = {
                "data": {
                    "timestamp": [int(pd.Timestamp(x).timestamp())*1000 for x in data["_time"]],
                    "value": [float(x) for x in data.iloc[:,4].values]
                }
                }
            station_data[sensor['measurement']] = data_dict
        station_data_dict = {"station_id":args['station_id'],"station_data":station_data}
        return jsonify(station_data_dict)

class GetStationSensors(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","message": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token})
        if claims.get('message'):
            return claims, 401
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        args = request.args
        stations = [station.Stations.id for station in crud.Stations.get_by_access(user_id=get_user_id(claims['sub']).Users.id)]
        if not args['station_id'] in stations:
            return {"message": "Forbidden", 'errors':["You do not have permission to access this station."]}, 403
        sensors = crud.MonitoredParameters.get_by_station_id(station_id=int(args['station_id']))
        response = [{'sensor_id':sensor.MonitoredParameters.id,'measurement':sensor.MonitoredParameters.measurement,'unit':sensor.MonitoredParameters.unit,'gauge_height':sensor.MonitoredParameters.device_height} for sensor in sensors]
        return response
    
class GetSensorData(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","errors": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token})
        if claims.get('message'):
            return claims, 401
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        args = request.args
        start = datetime.fromtimestamp(int(args["start"])/1000) if "start" in args.keys() else  (datetime.now() - timedelta(days = 3))
        end =  datetime.fromtimestamp(int(args["end"])/1000) if "end" in args.keys() else  datetime.now()
        if end > start:
            return {'message':'Bad request','errors':['end time should be later than start time']}, 400
        if (end - start).days > 3:
            return {'message':'Bad request','errors':['The requested time period exceeds the allowed 3 days maximum']}, 400
        sensor_info = crud.MonitoredParameters.get_by_id(id = int(args['sensor_id']))
        unit = sensor_info.MonitoredParameters.unit
        measurement =sensor_info.MonitoredParameters.measurement
        flux = influx.DataManagement(bucket_name='sensors_meters', organization='envrio', conf_file='C:/Users/xylop/Documents/github_repos/.certification_files/envrio_config.ini')
        data = flux.query_data(measurement=measurement, sensor_id=args["sensor_id"], unit=unit, start=start, stop=end)
        data_dict = {
            "sensor_id": args["sensor_id"],
            "measurement": measurement,
            "data": {
                "timestamp": [int(pd.Timestamp(x).timestamp())*1000 for x in data["_time"]],
                "value": [float(x) for x in data.iloc[:,4].values]
            }
            }
        return jsonify(data_dict)

api.add_resource(Authentication,f'/{prefix}/auth')
api.add_resource(GetStations,f'/{prefix}/stations')
api.add_resource(GetStationSensors,f'/{prefix}/station_sensors')
api.add_resource(GetStationData,f'/{prefix}/station_data')
api.add_resource(GetSensorData,f'/{prefix}/sensor_data')

def get_token(header: str) -> str:
    match header.split(" "):
        case ["Bearer", token]:
            return token
        
def get_user_id(name: str):
    return crud.User.get_by_name(name=name)

