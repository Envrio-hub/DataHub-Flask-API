__version__="1.0.1"
__author__='Ioannis Tsakmakis'
__date_created__='2023-11-21'

from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_cors import CORS
from datetime import datetime, timedelta
import pandas as pd
from databases_library import crud, influx
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

        with open('cognito.json','r') as f:
            cognito = json.load(f)

        client = boto3.client('cognito-idp',region_name=cognito['region'],
                              aws_access_key_id=cognito['access_key_id'], aws_secret_access_key=cognito['secret_access_key'])
        
        cognito = CognitoIdentityProviderWrapper(cognito_idp_client=client, user_pool_id=cognito['user_pool_id'],
                                                 client_id=cognito['client_id'], client_secret=cognito['client_secret'])
        
        response = cognito.start_sign_in(user_name=data['username'], password=data['password'])
        
        if response.get('AuthenticationResult'):
            subscription_status = crud.User.get_by_email(email=data['username']).subscription_expires_in
            if subscription_status == "inf":
               return {'message':'succefull authentication','access_token':response['AuthenticationResult']['AccessToken']}
            else:
                response = {'message':'Unauthorized','errors':['Your subscription has expired']} if datetime.strptime(subscription_status,"%Y-%m-%d") < datetime.now() else {'message':'succefull authendication','access_token':response['AuthenticationResult']['AccessToken']}
                return response
        else:
            return {'message':response['code'],'errors':[response['message']]}, 401


class GetStations(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","errors": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token}, None)
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        stations = crud.Stations.get_by_access(user_id=get_user_id(claims['sub']).id)
        response = [{"station_id":station.id,"date_created":station.date_created,"longitude":float(station.longitude),
                     "latitude":float(station.latitude),"elevation":station.elevation,"name":station.name['en']} for station in stations]
        return response

class GetStationSensors(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","message": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token}, None)
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        args = request.args
        sensors = crud.SensorsMeters.get_by_station_id(station_id=int(args['station_id']))
        response = [{'sensor_id':sensor.id,'measurement':sensor.measurement,'unit':sensor.unit,'gauge_height':sensor.gauge_height} for sensor in sensors]
        return response     
class GetSensorData(Resource):

    def get(self):
        if request.headers.get('Authorization'):
            header = request.headers['Authorization']
        else:
            return {'message': "Unauthorized","errors": ["No Beare Token"]}, 401
        access_token = get_token(header)
        decoder = DecodeVerifyJWT(user_pool_id='eu-west-1_Nxnijpx3x',client_id='6sqqmlb0m56mitarbdekd6c8tr', region_name='eu-west-1')
        claims = decoder.lambda_handler({'token':access_token}, None)
        if datetime.fromtimestamp(claims['exp']) < datetime.now():
            return {'message':'Unauthorized','errors': ['expired token']}, 401
        args = request.args
        start = datetime.fromtimestamp(int(args["start"])/1000) if "start" in args.keys() else  (datetime.now() - timedelta(days = 3))
        end =  datetime.fromtimestamp(int(args["end"])/1000) if "end" in args.keys() else  datetime.now()
        if (end - start).days > 3:
            return {'message':'Bad request','errors':['The requested time period exceeds the allowed 3 days maximum']}, 400
        sensor_info = crud.SensorsMeters.get_by_id(id = int(args['sensor_id']))
        unit = sensor_info.unit
        measurement =sensor_info.measurement
        flux = influx.InfluxDB(bucket_name='sensors_meters', organization='envrio', conf_file='envrio_config.ini')
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

class IternalGetSensorData(Resource):

    def get(self):
        flux = influx.InfluxDB(bucket_name='sensors_meters', organization='envrio', conf_file='envrio_config.ini')
        args = request.args
        sensor_info = crud.SensorsMeters.get_by_id(id = int(args['sensor_id']))
        unit = sensor_info.unit
        measurement =sensor_info.measurement
        start = datetime.fromtimestamp(int(args["start"])/1000) if "start" in args.keys() else  (datetime.now() - timedelta(days = 3))
        end =  datetime.fromtimestamp(int(args["end"])/1000) if "end" in args.keys() else  datetime.now()
        data = flux.query_data(measurement=measurement,sensor_id=args["sensor_id"],unit=unit,start=start,stop=end)
        data_dict = {
                  "date_time": [int(pd.Timestamp(x).timestamp())*1000 for x in data["_time"]],
                  "value": [float(x) for x in data.iloc[:,4].values]
             }
        return jsonify(data_dict)


api.add_resource(Authentication,f'/{prefix}/auth')
api.add_resource(GetStations,f'/{prefix}/stations')
api.add_resource(GetStationSensors,f'/{prefix}/station_sensors')
api.add_resource(GetSensorData,f'/{prefix}/sensor_data')
api.add_resource(IternalGetSensorData,f'/{prefix}/get_data')

def get_token(header: str) -> str:
    match header.split(" "):
        case ["Bearer", token]:
            return token
        
def get_user_id(name: str):
    return crud.User.get_by_name(name=name)

