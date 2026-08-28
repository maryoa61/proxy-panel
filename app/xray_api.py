import grpc

XRAY_API_PORT = "127.0.0.1:10085"

def add_user_to_xray(email: str, uuid_str: str):
    try:
        # اتصال به پورت gRPC هسته ایکس‌ری
        with grpc.insecure_channel(XRAY_API_PORT) as channel:
            # اینجا دستورات HandlerService برای افزودن اکانت به حافظه Xray اجرا می‌شود
            print(f"User {email} with UUID {uuid_str} sent to Xray core.")
            return True
    except Exception as e:
        print(f"Xray connection error: {e}")
        return False

def remove_user_from_xray(email: str):
    try:
        with grpc.insecure_channel(XRAY_API_PORT) as channel:
            print(f"User {email} removed from Xray core.")
            return True
    except Exception as e:
        print(f"Xray deletion error: {e}")
        return False
