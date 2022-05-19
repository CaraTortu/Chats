/*
    Created by: Javier Díaz on 19/04/22.
    https://github.com/CaraTortu/Chats
*/

$('#signup').on("click", function() {
  var x = this.id;
  $("#" + x).removeClass("s-atbottom");
  $("#" + x).addClass("s-attop");
  $("#login").removeClass("l-attop");
  $("#login").addClass("l-atbottom");
});

$('#login').on("click", function() {
  var x = this.id;
  $("#" + x).removeClass("l-atbottom");
  $("#" + x).addClass("l-attop");
  $("#signup").removeClass("s-attop");
  $("#signup").addClass("s-atbottom");
});

function login() {
  var user = document.getElementById('username-login').value
  var password = document.getElementById('password-login').value
  var remmemberme = document.getElementById('rememberme').checked

  if (user == "" || password == "") {
    document.getElementById('login-error').innerHTML = "Please fill in all fields";
    return false;
  }

  var data = JSON.stringify({
    "username": user,
    "password": password,
    "rememberme": remmemberme
  });

  $.ajax({
    type: "POST",
    url: "/api/login",
    contentType: 'application/json',
    data: data,
    success: function(r) { 
      if (r == "success") {
        window.location.href = "/tfa";
      }
      else {
        document.getElementById('login-error').innerHTML = r;
      }
    }
    });
    return false;
}

function signup() {
  var user = document.getElementById('username-signup').value
  var password = document.getElementById('password-signup').value
  var email = document.getElementById('email-signup').value

  if (user == "" || password == "" || email == "") {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Please fill in all fields";
    return false;
  }
  if (!isEmailValid(email)) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Please enter a valid email";
    return false;
  }
  // Check password length
  if (password.length < 8) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Password must be at least 8 characters";
    return false;
  }
  // Check password numbers
  if (password.match(/[0-9]/g) == null) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Password must contain at least one number";
    return false;
  }
  // Check password uppercase
  if (password.match(/[A-Z]/g) == null) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Password must contain at least one uppercase letter";
    return false;
  }
  // Check password lowercase
  if (password.match(/[a-z]/g) == null) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Password must contain at least one lowercase letter";
    return false;
  }
  // Check password special character
  if (password.match(/[!@#$%^&*()]/g) == null) {
    $('#signup-error').removeClass().addClass("error");
    document.getElementById('signup-error').innerHTML = "Password must contain at least one special character";
    return false;
  }


  var data = JSON.stringify({
    "username": user,
    "password": password,
    "email": email
  });

  $.ajax({
    type: "POST",
    url: "/api/signup",
    contentType: 'application/json',
    data: data,
    success: function(r) { 
      if (r == "success") {
        $('#signup-error').removeClass().addClass("right");
        document.getElementById('signup-error').innerHTML = "User created successfully, verification email sent!";
        delay(2000).then(() => window.location.href = "/login");
      }
      else {
        $('#signup-error').removeClass().addClass("error");
        document.getElementById('signup-error').innerHTML = r;
      }
    }
    });
    return false;
}

function isEmailValid(email) {
  const emailRegexp = new RegExp(
    /^[a-zA-Z0-9][\-_\.\+\!\#\$\%\&\'\*\/\=\?\^\`\{\|]{0,1}([a-zA-Z0-9][\-_\.\+\!\#\$\%\&\'\*\/\=\?\^\`\{\|]{0,1})*[a-zA-Z0-9]@[a-zA-Z0-9][-\.]{0,1}([a-zA-Z][-\.]{0,1})*[a-zA-Z0-9]\.[a-zA-Z0-9]{1,}([\.\-]{0,1}[a-zA-Z]){0,}[a-zA-Z0-9]{0,}$/i
  )

  return emailRegexp.test(email)
}

function delay(time) {
  return new Promise(resolve => setTimeout(resolve, time));
}
