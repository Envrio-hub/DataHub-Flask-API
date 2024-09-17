import requests

user_info = {
    "username": "your_username",
    "password": "your_password"
}

main_url = 'https://envrio.org/api/'

'''Create a valid token'''
authendicate = requests.post(f'{main_url}/api/auth', json=user_info)
print('\nResponse Status Code: ', authendicate.status_code, '\nResponse Message: ', authendicate.json())

'''Define the headers if the response is 200 and returns a valid access token'''
if authendicate.json().get('access_token'):
    headers = {
        'Authorization': f'Bearer {authendicate.json()['access_token']}'
    }

'''Returns information about the user registered stations'''
get_stations_info = requests(f'{main_url}/stations', headers=headers)
print('\nResponse Status Code: ', get_stations_info.status_code, '\nResponse Message: ', get_stations_info.json())

'''GET data from a station using a station id key. The station id can be retrieved running a get_station_info request.
Data for all the the station sensors will be returned for a period of three days from the request datetime.'''
get_station_data = requests(f'{main_url}/station_data', headers=headers, params = {'station_id': 'YOUR STATION ID NUMBER'})
print('\nResponse Status Code: ', get_station_data.status_code, '\nResponse Message: ', get_station_data.json())

'''GET information about a station sensors and meters using a station id key.'''
get_station_sensors = requests(f'{main_url}/station_sensors', headers=headers, params = {'station_id': 'YOUR STATION ID NUMBER'})
print('\nResponse Status Code: ', get_station_sensors.status_code, '\nResponse Message: ', get_station_sensors.json())

'''GET sensor data using a sensor id key. The key can be retrieved running a get_station_sensors request.
If a start and end time are not defined, data for three days since the request is submitted will be returned'''
params = {
    "sensor_id": 'YOUR STATION ID NUMBER',
    "start": "the timestamp that data will be retrieved from",
    "end": "the timestamp that data will be retrieved to"
}
get_sensor_data = requests(f'{main_url}/sensor_data', headers=headers, params = params)
print('\nResponse Status Code: ', get_sensor_data.status_code, '\nResponse Message: ', get_sensor_data.json())