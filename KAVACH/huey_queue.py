import os
from huey import SqliteHuey

db_path = os.path.join(os.path.dirname(__file__), 'huey_queue.db')
huey = SqliteHuey(filename=db_path)
