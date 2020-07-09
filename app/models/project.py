import uuid
import datetime
from app.common.database import Database


class Project(object):
    # we can have default parameters in the end id=None
    def __init__(self, project_id, user_id, pname, ptype, dataset, date, _id=None):
        # id = post id, blog_id = blog id,
        self.pname = pname
        self.ptype = ptype
        self.dataset = dataset
        self.user_id = user_id
        self.date = date
        self.project_id = uuid.uuid4().int if project_id is None else project_id
        # generate a random id if we haven't got any id
        self._id = uuid.uuid4().int if _id is None else _id

    #save data to mongo
    def save_to_mongo(self):
        print(self.json())
        Database.insert(collection = 'projects', data = self.json())

    # convert the data into json format
    def json(self):
        return {
            'project_id':  self.project_id,
            'user_id':  self.user_id,
            'pname':    self.pname,
            'in_training': False,
            'model_available': False,
            'ptype':    self.ptype,
            'dataset': self.dataset,
            'datetime':   self.date,
        }

    # @staticmethod
    # # return all posts with id = 'id' from collection = 'posts'
    # def from_mongo(id):
    #     return Database.find_one(collection='posts', query={'id':id})


    # we will use @classmethod instead of @staticmethod - the result will be an object
    @classmethod
    def from_mongo(cls, id):
        post_data = Database.find_one(collection='projects', query={'_id':id})
        return cls(**post_data)


    @staticmethod
    # return all posts belonging to the blog with blog_id
    # return a list of them - list comprehension
    def from_user(user_id):
        data = [post for post in Database.find(collection='projects', query={'user_id':user_id})]
        return data


    @staticmethod
    # return all posts belonging to the blog with blog_id
    # return a list of them - list comprehension
    def get_one(user_id, project_id):
        return [post for post in Database.find(collection='projects', query={'user_id':user_id, 'project_id':project_id})]

    @staticmethod
    # return all posts belonging to the blog with blog_id
    # return a list of them - list comprehension
    def check_auth(user_id, project_id):
        data = Project.get_one(int(user_id), int(project_id))
        print('check_auth', data)
        if len(data) == 0:
            return False
        return True