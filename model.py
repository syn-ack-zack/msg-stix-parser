from peewee import *
from playhouse.postgres_ext import *
from flask_login import UserMixin

db = PostgresqlExtDatabase(
    'flask',
    user='flask',
    password='',
    register_hstore=False
)

class BaseModel(Model):
    """A base model that will use our Postgresql database"""
    class Meta:
        database = db

def email_search(query):
    if len(query) > 0:
        query = "'%s'"%(query)
        return Email.select().where(Match(Email.raw_body,query))
    else:
        return ""

class Email(BaseModel):
    raw_header = TextField()
    raw_body = TextField()
    attachments = TextField()
    email_hash = TextField()
    email_raw = BlobField()

# Declare an Object Model for the user, and make it comply with the 
# flask-login UserMixin mixin.
class User(UserMixin):
    def __init__(self, dn, username, data):
        self.dn = dn
        self.username = username
        self.data = data

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

if __name__ == "__main__":
	try:
		Email.create_table()
	except OperationalError:
		print "Email table already exists"
