package UAM.UAM_PROJECT;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
/**
 * Root resource (exposed at "myresource" path)
 */
@Path("myresource")
public class MyResource {

    /**
     * Method handling HTTP GET requests. The returned object will be sent
     * to the client as "text/plain" media type.
     *
     * @return String that will be returned as a text/plain response.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getIt() {
        return "Got it!";
    }
    @GET
    @Path("db")
    public String connectDb() throws Exception {
    	Connection c= Db.connect();
    	if(c!=null)
    		return "connected";
    	else
    		return "not connected";
    }
    
    
	/*
	 * public String addRow(String UserName, String FirstName, String LastName,
	 * String Email, String PassWord) throws Exception { Connection c= Db.connect();
	 * Statement ShowState=c.createStatement(); String query="insert into emp"
	 * 
	 * }
	 */
   

	@Path("login")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public void login_page(@FormParam("username") String username,
                                     @FormParam("pass") String password,@Context HttpServletResponse response,@Context HttpServletRequest request) throws Exception {
            checkuser obj= new checkuser();
            HttpSession sess=request.getSession();
            sess.setAttribute("nameofuser",username);
            if(obj.authenticate(username, password)) {
            	String query = "SELECT * FROM user WHERE username = ?";
                Connection con=Db.connect();
                PreparedStatement pst = con.prepareStatement(query);
                pst.setString(1, username);
                ResultSet rs = pst.executeQuery();
                if(rs.next()) {
                	if ("admin".equals(rs.getString("usertype")) || "Admin".equals(rs.getString("usertype"))) {
                	    response.sendRedirect("http://localhost:9002/UAM_PROJECT/adminmainpage.html?username=" + URLEncoder.encode(username, "UTF-8"));
                	}

                	else if("user".equals(rs.getString("usertype")) || "User".equals(rs.getString("usertype"))){
                		response.sendRedirect("http://localhost:9002/UAM_PROJECT/usermainpage.html?username=" + URLEncoder.encode(username,"UTF-8"));
                	}
                	else {
                		response.sendRedirect("http://localhost:9002/UAM_PROJECT/managermain.html?username=" + URLEncoder.encode(username,"UTF-8"));
                	}
                }
            }
            
    }
    	
    
    
    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String registration_page(@FormParam("firstname")String firstname,
    		@FormParam("lastname")String lastname,
    		@FormParam("email")String email,
    		@FormParam("password")String password,
    		@FormParam("cpassword")String cpassword) throws Exception {
    	checkuser obj=new checkuser(firstname, lastname, email, password, cpassword);
    	if(checkuser.secondpassword()) {
    		return "Your username is: "+obj.insertUser()+"<br>"+"<a href='http://localhost:9002/UAM_PROJECT/index.jsp'>Login</a>";
    					
    	}
    	else {
    		return "check your entered data";
    	}
    }
    
    


    @Path("reset-password")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public String resetForgottenPassword(@FormParam("username") String username,
                                         @FormParam("email") String email,
                                         @FormParam("newpassword") String newPassword,
                                         @FormParam("confirmnewpassword") String confirmNewPassword) throws Exception {
        checkuser obj = new checkuser();

        
        if (!obj.usernameExists(username)) {
            return "Username not found.";
        }

        
        if (!obj.emailMatchesUsername(username, email)) { // Method to verify email and username match
            return "Email does not match the provided username.";
        }

        
        if (!newPassword.equals(confirmNewPassword)) {
            return "New password and confirm password do not match.";
        }

       
        String encryptedPassword = checkuser.encrypt(newPassword);

       
        String query = "UPDATE user SET pwd = ? WHERE username = ?";
        Connection con = Db.connect();
        PreparedStatement pst = con.prepareStatement(query);
        pst.setString(1, encryptedPassword);
        pst.setString(2, username);

        int rowsUpdated = pst.executeUpdate();
        if (rowsUpdated > 0) {
            return "Password reset successfully.";
        } else {
            return "Failed to reset password. Please try again.";
        }
    }

    
    @Path("update-password")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public String updatePassword(@Context HttpServletRequest request,
                                 @FormParam("currentpassword") String currentPassword,
                                 @FormParam("newpassword") String newPassword,
                                 @FormParam("confirmnewpassword") String confirmNewPassword) throws Exception {
        checkuser obj = new checkuser();

        
        HttpSession sess=request.getSession();
        String username=sess.getAttribute("nameofuser").toString();


        String storedPassword = obj.getPasswordForUsername(username); // This method should retrieve the stored (encrypted) password
        if (!checkuser.encrypt(currentPassword).equals(storedPassword)) {
            return "Current password is incorrect.";
        }

        if (!newPassword.equals(confirmNewPassword)) {
            return "New password and confirm password do not match.";
        }

        String encryptedPassword = checkuser.encrypt(newPassword);
        String query = "UPDATE user SET pwd = ? WHERE username = ?";
        Connection con = Db.connect();
        PreparedStatement pst = con.prepareStatement(query);
        pst.setString(1, encryptedPassword);
        pst.setString(2, username);

        int rowsUpdated = pst.executeUpdate();
        if (rowsUpdated > 0) {
            return "Password updated successfully.";
        } else {
            return "Failed to update password. Please try again.";
        }
    }

    
    //admin 
    
    @Path("add-user")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public String insertUser(@FormParam("firstname") String firstname,
                             @FormParam("lastname") String lastname,
                             @FormParam("email") String email) throws Exception {

        // Establish database connection
        Connection c = Db.connect();
        
        // Ensure the email is unique
        checkuser obj = new checkuser(firstname, lastname, email);
        if (obj.emailExists(email)) {
            return "Email is already registered.";
        }

        // Generate the username and determine user type
        String username = obj.check_Duplicate();
        String usertype = obj.admin_user();
        
        // Set a static password
        String tempPassword = "12345";
        
        // Get current date for Date of Joining (Doj)
        String dateofjoin = new SimpleDateFormat("yyyy-MM-dd").format(Calendar.getInstance().getTime());

        // Insert the user into the database
        String sql = "INSERT INTO user (firstname, lastname, email, pwd, username, Doj, usertype) VALUES (?, ?, ?, ?, ?, ?, ?)";
        PreparedStatement statement = c.prepareStatement(sql);
        statement.setString(1, firstname);
        statement.setString(2, lastname);
        statement.setString(3, email);
        statement.setString(4, checkuser.encrypt(tempPassword)); // Encrypt the static password before storing
        statement.setString(5, username);
        statement.setString(6, dateofjoin);
        statement.setString(7, usertype);
        
        int rowsInserted = statement.executeUpdate();
        if (rowsInserted > 0) {
            return "User added successfully. Username: " + username + " Password: " + tempPassword;
        } else {
            return "Failed to add user. Please try again.";
        }
    }

    
    @Path("resourcesList")
    @GET
    public String list_of_resources() throws Exception {
		checkuser obj=new checkuser();
		return "<h3>List of resources:</h3>"+obj.resourcesList();
	}

    @Path("managerList")
    @GET
    public String list_of_managers() throws Exception {
    	checkuser obj=new checkuser();
		return "<h3>List of Managers:</h3>"+obj.managerList();
	}
    @Path("requestsList")
    @GET
    public String list_of_requests() throws Exception {
    	checkuser obj=new checkuser();
		return "<h3>List of Requests:</h3>"+obj.requestsList();
	}
    @Path("accept")
    @POST
    public String accept(@FormParam("requestId")String id,@FormParam("requestName")String request,@FormParam("requestedFrom")String name,@Context HttpRequest req) throws Exception {
    	Connection c=Db.connect();
    	if(request.equals("Admin") ) {
    		String acceptquery1="update user set usertype='Admin' where username=?";
        	PreparedStatement pst1=c.prepareStatement(acceptquery1);
        	pst1.setString(1, name);
        	pst1.executeUpdate();
    	}
    	else if(request.equals("Manager") ) {
    		String acceptquery1="update user set usertype='Manager' where username=?";
        	PreparedStatement pst1=c.prepareStatement(acceptquery1);
        	pst1.setString(1, name);
        	pst1.executeUpdate();
    	}
    	else {
    		String acceptquery1="insert into UserResource(UserName,Resource_Name) values (?,?)";
        	PreparedStatement pst1=c.prepareStatement(acceptquery1);
        	pst1.setString(1, name);
        	pst1.setString(2, request);
        	pst1.executeUpdate();
    	}
    	
    	String acceptquery2="delete from requests where RequestId=?";
    	PreparedStatement pst2=c.prepareStatement(acceptquery2);
    	pst2.setString(1, id);
    	pst2.executeUpdate();
    	return "<h1>Request got accepted by admin</h1>"+"<br><a href=''>Back</a>";
    }
    @Path("reject")
    @POST
    public String reject(@FormParam("requestId")String id,@Context HttpServletRequest req) throws Exception {
    	Connection c=Db.connect();
    	String query2="delete from requests where RequestId=?";
    	PreparedStatement pst2=c.prepareStatement(query2);
    	pst2.setString(1, id);
    	pst2.executeUpdate();
    	return "<h1>Request is Rejected</h1>"+"<br><a href=''>Back</a>";
    }
    

    @Path("useradd")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String addusers(@FormParam("firstname")String firstname,
    		@FormParam("lastname")String lastname,
    		@FormParam("email")String email,
    		@FormParam("password")String password,
    		@FormParam("confirmpassword")String confirmpassword) throws Exception {
    	checkuser obj=new checkuser(firstname, lastname, email, password, confirmpassword);
    	if (checkuser.secondpassword()) {
            // Passwords do not match
    		return "passwords did not match";
        }
    	return "User is added and his name is :"+obj.insertUser();
    }
    
    @Path("userremove")
    @GET
    public String remove_users(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=(String) session.getAttribute("nameofuser");
    	String s=obj.removeUser(name);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(227, s, "webapp/adminremoveusers.html", req);
    }
    @Path("userremove1")
    @POST
    public String remove_users1(@FormParam("options")String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	return obj.removeuser1(options);
    }

    @Path("addAsset")
    @POST
    public String add_resources(@FormParam("resourcename")String resourcename) throws Exception {
    	checkuser obj=new checkuser();
    	
		if(obj.addResources(resourcename)) {
			return "Resource is added.";
		}
		return "Resource already exists.";
	}

    @Path("resourcesremoved")
    @GET
    public String remove_resources(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		FileUtils fobj=new FileUtils();
		String s=obj.resourcesremoved();
		return fobj.addDataAfter(228, s, "webapp/adminremoveresources.html", req);
	}

    @Path("resourcesremoved1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String remove_resources1(@FormParam("options")String options) throws Exception {
    	checkuser obj=new checkuser();
		return obj.resourcesremoved1(options);
		

	}
    @Path("changingpasswordforadmin")
    @GET
    public String change_password_admin(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		FileUtils fobj=new FileUtils();
		String s=obj.adminpasswordchange();
		return  fobj.addDataAfter(185, s, "webapp/Adminbase.html", req);
    }
    @Path("changingpasswordforadmin1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String change_password1_admin(@FormParam("newpassword")String p,@FormParam("confirmnewpassword")String q,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	if(p.equals(q)) {
    		HttpSession session=req.getSession();
    		String name=session.getAttribute("nameofuser").toString();
        	return obj.changepassword1(name,p)+"<br><a href=''>Go Back</a>";//where is this method change password
    	}
    	return "<h1>Passwords did not match</h1>";//link
    }
    @Path("removeresourcefromauser")
    @GET
    public String remove_resource_from_a_user(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	FileUtils fobj=new FileUtils();
    	String s=obj.removeresourceuser();
    	return fobj.addDataAfter(227, s,"webapp/adminremoveresourcefromauser.html", req);
    }
    @Path("removeresourcefromauser1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String remove_resource_from_a_user1(@FormParam("options1")String options1,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	FileUtils fobj=new FileUtils();
    	String s=obj.removeresourceuser1(options1);
    	return fobj.addDataAfter(227, s,"webapp/adminremoveresourcefromauser.html", req);
    }
    @Path("removeresourcefromauser2")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String remove_resource_from_a_user2(@FormParam("options2")String options2) throws Exception {
    	checkuser obj=new checkuser();
    	return obj.removeresourceuser2(options2);//link
    }
    
    @Path("checkingresourcesonuser")
    @GET
    public String check_users_for_a_resource(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.resourcecheckingusers();
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(229, s, "webapp/admincheckusersforaresource.html", req);
    }
    @Path("checkingresourcesonuser1")
    @POST
    public String check_users_for_a_resource1(@FormParam("options")String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s= obj.resourcecheckinguser1(options);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(229, s, "webapp/admincheckusersforaresource.html", req);
    }
    @Path("checkresourcesofuser")
    @GET
    public String check_resources_of_an_user(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.checkresourcesofuser();
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(230, s, "webapp/admincheckresourcesofanuser.html", req);
    }
    @Path("checkresourcesofuser1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String check_resources_of_an_user1(@FormParam("options")String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.checkresourcesofuser1(options);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(230, s, "webapp/admincheckresourcesofanuser.html", req);
    }
    @Path("assignresourcestoansuser")
    @GET
    public String assign_resources_to_an_suser(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.assignresourcestoanuser();
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(226, s, "webapp/adminassignresourcestoanuser.html", req);
    }

    @Path("assignresourcestoanuser1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String assign_resources_to_an_user1(@FormParam("options1")String options1,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.assignresourcestoanuser1(options1);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(226, s, "webapp/adminassignresourcestoanuser.html", req);
    }
    @Path("assignresourcestoanuser2")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String assign_resources_to_an_user2(@FormParam("options1")String options1,@FormParam("options2")String options2,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.assignresourcestoanuser2(options1,options2);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(226, s, "webapp/adminassignresourcestoanuser.html", req);
    }

    @Path("makeasadminormanager")
    @GET
    public String make_as_admin_or_manager(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.makeasadminormanager();
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(227, s, "webapp/adminmakeasadminormanager.html", req);
    }
    @Path("makeasadminormanager1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String make_as_admin_or_manager1(@FormParam("options1")String options1,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.makeasadminormanager1(options1);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(227, s, "webapp/adminmakeasadminormanager.html", req);
    }
    @Path("makeasadminormanager2")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String make_as_admin_or_manager2(@FormParam("options1")String options1,@FormParam("options2")String options2,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.makeasadminormanager2(options1,options2);
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(227, s, "webapp/adminmakeasadminormanager.html", req);
    }
    
    
    
    
    
    
    
    
    
    
    
    
    //manager starts
    @Path("managerteam")
    @GET
    public String show_managerteam(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=(String) session.getAttribute("nameofuser");
    	FileUtils fobj=new FileUtils();
    	String z=obj.teamList(name);
    	return fobj.addDataAfter(84,z, "webapp/managershow-team.html", req);
    }
    @Path("togetateammember")
    @GET
    public String to_get_a_team_member(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	String s=obj.getteammember();
    	FileUtils fobj=new FileUtils();
    	return fobj.addDataAfter(85, s, "webapp/managerget-team-member.html", req);
    }
    @Path("togetateammember1")
    @POST
    public String to_get_a_team_member1(@FormParam("options")String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=(String) session.getAttribute("nameofuser");
    	return obj.getteammember1(options, name);
    }
    
    @Path("requestaboutresourcesmanager")
    @GET
    public String request_about_resource_manager(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		HttpSession session=req.getSession();
		String name=(String) session.getAttribute("nameofuser");
		FileUtils fobj=new FileUtils();
		String s=obj.requestresourcesmanager(name);
		return  fobj.addDataAfter(84, s, "webapp/managerrequest-resource.html", req);
	}
    
    @Path("requestaboutresourcesmanage1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String request_for_resource1_manager(@FormParam("options") String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		HttpSession session=req.getSession();
		String s=session.getAttribute("nameofuser").toString();
		return  obj.requestresourcemanager1(options, s);
	}
    @Path("theresourccemanager")
    @GET
    public String my_resources_manager(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	String s=obj.myresources(name);
    	FileUtils fobj=new FileUtils();
		return  fobj.addDataAfter(84, s, "webapp/managermy-resources.html", req);
    }
    @Path("approvalchecking")
    @GET
    public String check_approvals_manager(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	return obj.checkforapprovals(name);
    }

    @Path("removingresourcesformanager")
    @GET
    public String remove_own_resource_manager(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	FileUtils fobj=new FileUtils();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	String s=obj.removeownresourcesmanager(name);
    	return fobj.addDataAfter(85, s,"webapp/managerremove-own-resources.html" , req);
    }
    @Path("removingresourcesformanage1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String remove_resource1_manager(@FormParam("options") String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();

		return  obj.resourcesremoved1(options);
	}
    @Path("positionreqasadmin")
    @GET
    public String request_for_admin(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=(String) session.getAttribute("nameofuser");
    	Connection c = Db.connect();
	    String query = "SELECT 1 FROM requests WHERE Requestedfrom=? AND requestname=?";
	    PreparedStatement pst = c.prepareStatement(query);
	    pst.setString(1, name);
	    pst.setString(2, "Admin");
	    ResultSet rs = pst.executeQuery();
	    String dropDown="<form action='positionreqasadmin1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select For Requesting:</label>"+
				"<select id='dropdown' name='options'>";
	    if(!rs.next()) {
	    	String value="Admin";
        	dropDown+="<option value='"+value+"'>"+value+"</option>";
	    }
	    else {
	    	dropDown+="<option value=''>No options available</option>";
	    }
	    dropDown+="</select>";	
        dropDown+="<button type='submit'>Submit</button>";
        dropDown+="</form>";
	    FileUtils fobj=new FileUtils();
	    return fobj.addDataAfter(85, dropDown, "webapp/managerrequest-admin.html", req);
    }
    @Path("positionreqasadmin1")
    @POST
    public String request_for_admin1(@FormParam("options")String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=(String) session.getAttribute("nameofuser");
    	return obj.requestingformanager(options,name);//check here this method have options and name
    }
   
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
//user
    
    @Path("resourcesarerequested")
    @GET
    public String request_for_resource(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		HttpSession session=req.getSession();
		String name=(String) session.getAttribute("nameofuser");
		FileUtils fobj=new FileUtils();
		String s=obj.requestingforresources(name);
		return  fobj.addDataAfter(173, s, "webapp/userrequestforresources.html", req);
	}

    @Path("resourcesarerequested1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String request_for_resource1(@FormParam("options") String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		HttpSession session=req.getSession();
		String s=session.getAttribute("nameofuser").toString();
		return  obj.requestingforresource1(options, s);
	}

    @Path("checkingapprovals")
    @GET
    public String check_approvals(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	return obj.checkforapprovals(name);
    }

    @Path("resourcesofmine")
    @GET
    public String my_resources(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	String s=obj.myresources(name);
    	FileUtils fobj=new FileUtils();
		return  fobj.addDataAfter(173, s, "webapp/usermyresources.html", req);
    }

    @Path("removingownresource")
    @GET
    public String remove_own_resource(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	FileUtils fobj=new FileUtils();
    	HttpSession session=req.getSession();
    	String name=session.getAttribute("nameofuser").toString();
    	String s=obj.removeourresource(name);
    	return fobj.addDataAfter(173, s,"webapp/userremoveownresource.html" , req);
    }
    @Path("resourceremoved1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String remove_resource1(@FormParam("options") String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
		return  obj.removingresource1(options);
    }
    @Path("requestingfor")
    @GET
    public String request_for(@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
		String name=session.getAttribute("nameofuser").toString();
		FileUtils fobj=new FileUtils();
		String s=obj.requestingfor(name);
		return  fobj.addDataAfter(173, s, "webapp/userrequestfor.html", req);
    }
    @Path("requestingfor1")
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public String request_for1(@FormParam("options") String options,@Context HttpServletRequest req) throws Exception {
    	checkuser obj=new checkuser();
    	HttpSession session=req.getSession();
		String name=session.getAttribute("nameofuser").toString();
    	return obj.requestingfor1(options, name);
    }
    //@Path("newpassword")
   // @GET
   // public String change_password(@Context HttpServletRequest req) throws Exception {
   // 	checkuser obj=new checkuser();
	//	FileUtils fobj=new FileUtils();
		//String s=obj.changepassword();
		//return  fobj.addDataAfter(140, s, "webapp/requestforresource.html", req);
    //}
}
