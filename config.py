import os


class Config:
    # SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql:///crud.db')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'mysql+pymysql://vpnmanager:nopwd@192.168.100.204:3306/vpnmanager')

    SQLALCHEMY_TRACK_MODIFICATIONS = False


router_user = ""
router_password = ""
