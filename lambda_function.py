import json
import pg8000
import os
import jwt

def lambda_handler(event, context):
    token = event['headers'].get('Authorization')
    token = remove_bearer_string(token)
    method_arn = event['methodArn']
    
    print(f"Authorization Token: {token}")
    print(f"Method ARN: {method_arn}")
    
    if token:
        try:
            cpf_from_token = get_cpf_from_jwt_token(token)
            if is_valid_customer(cpf_from_token):
                return generate_policy('user', 'Allow', method_arn)
            return generate_policy('user', 'Deny', method_arn)
        except Exception as e:
            print(f"Error decoding token: {e}")
            return generate_policy('user', 'Deny', method_arn)
    else:
        raise Exception('Unauthorized')

def get_cpf_from_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, os.environ['SECRET_KEY'], algorithms=['HS256'])
        return payload.get('cpf')
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

def remove_bearer_string(token: str) -> str:
    return token.replace("Bearer ", "")

def is_valid_customer(cpf_from_token: str) -> bool:
    db_host = os.environ['DB_HOST']
    db_name = os.environ['DB_NAME']
    db_user = os.environ['DB_USER']
    db_password = os.environ['DB_PASSWORD']
    
    query = f"SELECT COUNT(cpf) FROM customer WHERE cpf = '{cpf_from_token}';"

    try:
        connection = pg8000.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
        )
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        return True if result[0] == 1 else False

    except Exception as e:
        print(f"SQL execution failed: {e}")
        return False


def generate_policy(principal_id, effect, resource) -> dict:
    auth_response = {}
    auth_response['principalId'] = principal_id
    
    if effect and resource:
        policy_document = {}
        policy_document['Version'] = '2012-10-17'
        policy_document['Statement'] = []
        
        statement = {}
        statement['Action'] = 'execute-api:Invoke'
        statement['Effect'] = effect
        statement['Resource'] = resource
        
        policy_document['Statement'].append(statement)
        auth_response['policyDocument'] = policy_document
    
    return auth_response
