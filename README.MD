## Backend Test Web App
URL => https://desolate-chamber-59976.herokuapp.com
#### REST API endpoints

* Create Account - https://desolate-chamber-59976.herokuapp.com/api/account/new
    POST -Body {"email" : mail, "password" : password}

* Authenticate Account - https://desolate-chamber-59976.herokuapp.com/api/account/authenticate
    POST -Body {"email" : mail, "password" : password}

* Update Account Details - https://desolate-chamber-59976.herokuapp.com/api/account/update
    POST -Header AuthorizationKey -Body {"fullname" : name, "telephone" : phone, "address" : address}

* Fetch Current User Profile - https://desolate-chamber-59976.herokuapp.com/api/me/profile
    GET -Header AuthorizationKey

* Fetch Other User's Profile - https://desolate-chamber-59976.herokuapp.com/api/profile/{id}
    GET -Header AuthorizationKey

Thank You!