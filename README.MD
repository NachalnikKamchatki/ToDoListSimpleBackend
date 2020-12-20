# TODO_LIST


## REST API Flask приложение с аутентификацией с помощью JSON Web Token


### Использование
Запустить сервер командой py manage.py runserver


### Маршруты
- /todo/api/v1.0/register - Регистрация нового пользователя. В теле запроса указать 
  json {"name": "Your-Name", "password": "your-password"}. В ответ придет {'message': 'registered successfully'}
  
- /todo/api/v1.0/login - Авторизация пользователя. В заголовка запроса указать базовую авторизацию
  и логин с паролем использовавшимся при регистрации. В ответ придет {"token": "your-token"}
  
- /todo/api/v1.0/tasks. Требует авторизацию. Возвращает список задач авторизованного пользователя.

- /todo/api/v1.0/tasks/<<int:task_id>> Требует авторизацию. Возвращает задачу с номером task_id авторизованного пользователя.

- /todo/api/v1.0/tasks Требует авторизацию. Метод POST. Добавляет в базу данных задачу, кторая передается в теле запроса в виде:
{"title": "Task title", "description": "Task description"}. Возвращает в случае успеха {'status': 'success'}
  
- /todo/api/v1.0/tasks/<<int:task_id>> Требует авторизацию. Метод PUT. Изменяет запись с номером task_id в базе данных, изменения передаются в теле запроса в виде:
{"title": "other title"}. Возвращает в случае успеха {'status': 'success'}
  
- /todo/api/v1.0/tasks/<<int:task_id>> Требует авторизацию. Метод DELETE.  запись в базе данных, изменения передаются в теле запроса в виде:
{"title": "other title"}. Возвращает в случае успеха {'status': 'success'}

