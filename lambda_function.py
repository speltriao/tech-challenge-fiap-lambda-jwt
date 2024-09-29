import json
import jwt

def lambda_handler(event, context):
    body = json.loads(event.get("body", "{}"))
    cpf = body.get("cpf")
    
    if not cpf or cpf == '':
        cpf = os.environ['DEFAULT_CPF'] # O usuário escolheu não se autenticar
    
    if not is_valid_customer(cpf):
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Usuário não cadastrado"})
        }

    secret = os.environ['SECRET']
    payload = {
        "cpf": cpf
    }
    
    token = jwt.encode(payload, secret, algorithm="HS256")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "token": token
        })
    }

def is_valid_customer(cpf: str) -> bool:
    db_host = os.environ['DB_HOST']
    db_name = os.environ['DB_NAME']
    db_user = os.environ['DB_USER']
    db_password = os.environ['DB_PASSWORD']
    
    query = f"SELECT COUNT(cpf) FROM customer WHERE cpf = '{cpf}';"

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
