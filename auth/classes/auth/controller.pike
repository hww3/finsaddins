import Fins;

inherit Fins.DocController;

//! this is a sample authentication handler module which can be customized
//! to fit the particular needs of your application
//!
//! this provider uses a form to gather authentication information
//! and stores the validated user identifier (what that actually is 
//! will depend on the behavior of the @[find_user] method) in the 
//! session.
//! 
//! the application may pass "return_to" in the request variable mapping
//! which will be used to determine the url the application will return to
//! following a successful authentication.

//! method which is called to determine if a user should be authenticated.
//! this method accepts the request object and should return 
//! zero if the user was not successfully authenticated, or a value
//! which will be placed in the current session as "user".
function(Fins.Request,Fins.Response,Fins.Template.View:mixed) find_user = default_find_user;

//! method which is called to locate a user's password.
//! this method accepts the request object and should return either a
//! user object with "email" and "password" fields, or a mapping with these
//! two indices.
function(Fins.Request,Fins.Response,Fins.Template.View:mixed) find_user_password = default_find_user_password;

//! 
object|function default_action;

//! default startup method. sets @[default_action] to be the root of the 
//! current application. custom applications should override this method 
//! and set this value appropriately.
static void start()
{
  default_action = app->controller;
}

//! default user authenticator
static mixed default_find_user(Request id, Response response, Template.View t)
{
  mixed r = Fins.Model.find.users( ([ "username": id->variables->username,
                                      "password": id->variables->password 
                                    ]) );

  t->add("username", id->variables->username);

  if(r && sizeof(r)) return r[0];
  else return 0;
}

//! the name of the template to use for sending the password via email.
string password_template_name = "auth/sendpassword";

//! default user authenticator
static mixed default_find_user_password(Request id, Response response, Template.View t)
{
  mixed r = Fins.Model.find.users( ([ "username": id->variables->username,
                                    ]) );

  t->add("username", id->variables->username);

  if(r && sizeof(r)) return r[0];
  else return 0;
}

//! override this method to set the mail host for retrieved password emails.
static string get_mail_host()
{
  return gethostname();
}

//! override this method to set the return address for retrieved password emails.
static string get_return_address()
{
  return "password-retrieval@" + gethostname();
}

// _login is used for ajaxy logins.
function _login = login;

public void login(Request id, Response response, Template.View t, mixed ... args)
{

   if(!id->variables->return_to)
   {
      id->variables->return_to = ((id->misc->flash && id->misc->flash->from) ||
                               id->variables->referrer || id->referrer ||
                               app->url_for_action(default_action));
   }

   switch(id->variables->action)
   {
      case "Cancel":
         response->redirect(id->variables->return_to || default_action);
         return;
         break;
      default:
        mixed r = find_user(id, response, t);
        if(r)
        {
           // success!
           id->misc->session_variables->logout = 0;
           id->misc->session_variables["user"] = r[0];
           if(search(id->variables->return_to, "?") < -1)
             id->variables->return_to = id->variables->return_to + "&" + time();
           else
             id->variables->return_to = id->variables->return_to + "?" + time();
           response->redirect(id->variables->return_to || default_action);
           return;
        }
        else
        {
           response->flash("Login Incorrect.");
        }
   }

   t->add("return_to", id->variables->return_to);
}

public void logout(Request id, Response response, Template.View t, mixed ... args)
{
  if(id->misc->session_variables->userid)
  {
     id->misc->session_variables->logout = time();
     m_delete(id->misc->session_variables, "user");
  }

  response->flash("You have been successfully logged out.");
  response->redirect(id->referrer||default_action);
}

public void forgotpassword(Request id, Response response, Template.View t, mixed ... args)
{
  mixed r = find_user_password(id, response, t);

  if(!r)
  {
    response->flash("Unable to find a user account with that username. Please try again.\n");
  }
  else
  {
    object tp = view->get_idview(password_template_name);

    tp->add("password", r["password"]);

    string mailmsg = tp->render();

    Protocols.SMTP.Client(get_mail_host())->simple_mail(r["email"],
                              "Your FinScribe password",
                              get_return_address(),
                              mailmsg);

    response->flash("Your password has been located and will be sent to the email address on record for your account.\n");
    response->redirect(login);
   }
}
