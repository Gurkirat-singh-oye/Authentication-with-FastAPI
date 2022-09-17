from pymongo import MongoClient

db = MongoClient("mongodb+srv://jbd:Kirat@clusterjuan.c4ply.mongodb.net/?retryWrites=true&w=majority").SSdb
collec = db["EZusers"]