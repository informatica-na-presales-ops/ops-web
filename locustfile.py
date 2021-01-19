from locust import HttpUser, task

class OpsWebUser(HttpUser):
    @task
    def get_index(self):
        self.client.get('/')
