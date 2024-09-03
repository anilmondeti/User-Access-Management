package UAM.UAM_PROJECT;

import java.net.PasswordAuthentication;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;



public class checkuser {
	
	static String firstname="";
	static String lastname="";
	String email="";
	static String password="";
	static String conpassword="";
	String usertype="";
	String username="";
	
	
	//about resources
	
	String ResourcesName="";
	int NumberofResources=0;
	
	//Encryption password
	public checkuser(String firstname,String lastname,String email,String password,String conpassword) {
		checkuser.firstname=firstname;
		checkuser.lastname=lastname;
		this.email=email;
		checkuser.password=password;
		checkuser.conpassword=conpassword;
	}
	
	public checkuser(String username,String password) {
		this.username=username;
		checkuser.password=password;
		
	}
	public checkuser(String firstname,String lastname,String email) {
		checkuser.firstname=firstname;
		checkuser.lastname=lastname;
		this.email=email;
	}
	public checkuser() {
		// TODO Auto-generated constructor stub
	}
	
	
	// for the Resource
	public checkuser(String ResourcesName, int NumberofResources) {
		this.ResourcesName=ResourcesName;
		this.NumberofResources=NumberofResources;
		
	}

	public static String encrypt(String password) {
	    String giveninputfile = "ABCDEFGHI\r\n"
	                          + "JKLMNOPQR\r\n"
	                          + "STUVWXYZa\r\n"
	                          + "bcdefghij\r\n"
	                          + "klmnopqrs\r\n"
	                          + "tuvwxyz01\r\n"
	                          + "23456789`\r\n"
	                          + "~!@#$%^&*\r\n"
	                          + "()-_=+[{]\r\n"
	                          + "}|;:',<.>\r\n"
	                          + "/?\r\n";
	    
	    String[] rows = giveninputfile.split("\r\n");
	    StringBuilder res = new StringBuilder();
	    
	    for (int i = 0; i < rows.length; i++) {
	        for (int j = 0; j < rows[i].length(); j++) {
	            for (int k = 0; k < password.length(); k++) {
	                if (rows[i].charAt(j) == password.charAt(k)) {
	                    res.append(i + 1).append(j + 1);
	                }
	            }
	        }
	    }
	    return res.toString();
	}

	
//Duplicate password correction
	public static boolean secondpassword() {
		if (password.equals(conpassword)) {
			return true;
		}
		else {
			return false;
		}
	}
		
	
//Duplicate correction
	
	public static String check_Duplicate() throws Exception {
		Connection c=Db.connect();
		String username=firstname+"."+lastname;
		String s="select count(*) from user where username like ?";
		PreparedStatement pst=c.prepareStatement(s);
		pst.setString(1, username+"%");
		ResultSet rs=pst.executeQuery();
		int count=0;
		if(rs.next()) {
			count=rs.getInt(1);
		}
		if(count!=0) {
			username=username+count;
		}
        return username;
	}


//Registration encrypted
public String admin_user() throws Exception{
Connection c=Db.connect(); // assume this method returns a connection to the database
String sql = "SELECT * FROM user";
PreparedStatement statement = c.prepareStatement(sql);
ResultSet result = statement.executeQuery();
String usertype=null;
if (!result.next()) { // if the database is empty
    // create the first user as an admin
    usertype="admin";
} else {
    // create a regular user
	usertype="user";
}
return usertype;
}

//admin added the user
public boolean emailExists(String email) throws Exception {
    // Establish database connection
    Connection con = Db.connect();
    
    // SQL query to check if the email exists
    String query = "SELECT COUNT(*) FROM user WHERE email = ?";
    PreparedStatement pst = con.prepareStatement(query);
    pst.setString(1, email);
    
    // Execute the query
    ResultSet rs = pst.executeQuery();
    
    // Check the result
    rs.next();
    int count = rs.getInt(1);
    
    // Return true if email exists, otherwise false
    return count > 0;
}


// creating a new user
public String insertUser() throws Exception{
	Connection c=Db.connect();
	usertype=admin_user();
	String username=check_Duplicate();
String sql = "INSERT INTO user (firstname, lastname, email, pwd, username, Doj, usertype) VALUES (?, ?, ?, ?, ?, ?, ?)";
String dateofjoin = new SimpleDateFormat("yyyy-MM-dd").format(Calendar.getInstance().getTime());

PreparedStatement statement = c.prepareStatement(sql);
statement = c.prepareStatement(sql);
statement.setString(1, firstname);
statement.setString(2, lastname);
statement.setString(3, email);
statement.setString(5, username);
statement.setString(6, dateofjoin);
statement.setString(7, usertype);
statement.setString(4, checkuser.encrypt(password));
statement.executeUpdate();

return username;
}

//login
public String login_page() {
	try {
		Connection c=Db.connect();
    	String checkpassword="select pwd from user where username=?";
    	PreparedStatement pstlog=c.prepareStatement(checkpassword);
    	pstlog.setString(1, username);
    	ResultSet rs=pstlog.executeQuery();
    	if(rs.next()) {
    		if(password.equals(rs.getString("pwd"))) {
    			return "You have logged in successfully";
    		}
    		else {
    			return "You have entered wrong password";
    		}
    	}
	else {
    		return"check username or password";
    	}
	}
	catch(Exception e) {
		return e.getMessage();
	}
}

public String getPasswordForUsername(String username) throws Exception {
    String query = "SELECT pwd FROM user WHERE username = ?";
    try (Connection con = Db.connect();
         PreparedStatement pst = con.prepareStatement(query)) {
        pst.setString(1, username);
        try (ResultSet rs = pst.executeQuery()) {
            if (rs.next()) {
                return rs.getString("pwd");
            }
        }
    }
    return null;
}


public boolean usernameExists(String username) throws Exception {
    String query = "SELECT COUNT(*) FROM user WHERE username = ?";
    Connection con = Db.connect();
    PreparedStatement pst = con.prepareStatement(query);
    pst.setString(1, username);
    ResultSet rs = pst.executeQuery();
    rs.next();
    return rs.getInt(1) > 0;
}

public boolean emailMatchesUsername(String username, String email) throws Exception {
    Connection con = Db.connect();
    String query = "SELECT COUNT(*) FROM user WHERE username = ? AND email = ?";
    PreparedStatement pst = con.prepareStatement(query);
    pst.setString(1, username);
    pst.setString(2, email);
    ResultSet rs = pst.executeQuery();
    rs.next();
    return rs.getInt(1) > 0;
}

public boolean authenticate(String username, String password) throws Exception {
    Connection con = Db.connect();
    String query = "SELECT * FROM user WHERE pwd = ?";
    PreparedStatement pst = con.prepareStatement(query);
    String encryptedPassword = checkuser.encrypt(password);
    pst.setString(1, encryptedPassword);
    ResultSet rs = pst.executeQuery();
    boolean flag = false;

    while (rs.next()) {
        String storedUsername = rs.getString("username");
        if (storedUsername.equals(username)) {
            flag = true;
            break;
        }
    }
    return flag;
}		


//admin checking how many users we have

public String howmanyusers() throws Exception {
	Connection con=Db.connect();
	String howmanyusers_sql="select * from users";
	PreparedStatement pst = con.prepareStatement(howmanyusers_sql);
	ResultSet rs = pst.executeQuery();
	return rs.toString();
	
}

// add resources
public Boolean addResources(String resourcename) throws Exception {
	Connection con=Db.connect();
	String addResourceQuery="INSERT INTO resources (ResourcesName,NumberofResources) VALUES (?,?) ";
	String SelectResourceQuery="select ResourcesName from resources where lower(ResourcesName)=?";
	PreparedStatement pst1 = con.prepareStatement(SelectResourceQuery);
	pst1.setString(1, resourcename);
	ResultSet rst=pst1.executeQuery();
	if(rst.next()) {
		return false;
	}
	PreparedStatement pst = con.prepareStatement(addResourceQuery);
	pst.setString(1, resourcename);
	pst.setInt(2, 0);
	pst.executeUpdate();
	return true;
}
	
//list of resources

public String resourcesList() throws Exception {
	Connection con=Db.connect();
	String resourcesListquery="select * from resources";
	PreparedStatement pst=con.prepareStatement(resourcesListquery);
	ResultSet rs=pst.executeQuery();
	if(rs.equals(null)) {
		return "No resources";
	}
	String List="<table border='1'><tr><th>ResourceName</th></tr>";
	while(rs.next()) {
		List+="<tr>";
		List+="<td>"+rs.getString(1)+"</td>";
		List+="</tr>";
	}
	List+="</table>";
	return List;
}


//delete resources

public String removeResource() throws Exception {
    Connection con = Db.connect();
    String removeResourceQuery = "DELETE FROM resources WHERE ResourceName = ? AND NumberofResources = ?";
    PreparedStatement pst = con.prepareStatement(removeResourceQuery);
    pst.setString(1, ResourcesName);
    pst.setInt(2, NumberofResources);
    pst.executeUpdate();
    return removeResourceQuery;
}


//  list of managers
public String managerList() throws Exception {
	Connection con=Db.connect();
	String managerListquery="select * from user where usertype=?";
	PreparedStatement pst=con.prepareStatement(managerListquery);
	pst.setString(1, "Manager");
	ResultSet rs=pst.executeQuery();
	if(rs.equals(null)) {
		return "No resources";
	}
	String list="<table border='1'><tr><th>ManagerName</th></tr>";
	while(rs.next()) {
		list+="<tr>";
		list+="<td>"+rs.getString(5)+"</td>";
		list+="</tr>";
	}
	list+="</table>";
	return list;
}



//List of requests

public String requestsList() throws Exception {
    Connection con = Db.connect();
    // Query to get requests based on the username
    String requestslistquery = "select * from requests";
    PreparedStatement pst = con.prepareStatement(requestslistquery);
    ResultSet rs = pst.executeQuery();
    // StringBuilder to build the HTML table for requests and action buttons
    StringBuilder html = new StringBuilder("<table class='requests-table' style='width: 100%; border-collapse: collapse; font-family: Arial, sans-serif;'>");

 // Table headers
 html.append("<thead style='background-color: #f2f2f2;'>");
 html.append("<tr>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Request ID</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Requested From</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Requestee Type</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Date Of Requesting</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Request Name</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Approval</th>");
 html.append("<th style='padding: 12px; text-align: left; border-bottom: 2px solid #ddd;'>Actions</th>");
 html.append("</tr>");
 html.append("</thead>");

 // Table body
 html.append("<tbody>");
 while (rs.next()) {
     int requestId = rs.getInt("RequestId");
     String requestedFrom = rs.getString("Requestedfrom");
     String requesteeType = rs.getString("requesteetype");
     String dateOfRequesting = rs.getString("DOR");
     String requestName = rs.getString("requestname");
     String approval = rs.getString("ApprovalStatus");
     
     html.append("<tr style='border-bottom: 1px solid #ddd;'>");
     html.append("<td style='padding: 10px;'>").append(requestId).append("</td>");
     html.append("<td style='padding: 10px;'>").append(requestedFrom).append("</td>");
     html.append("<td style='padding: 10px;'>").append(requesteeType).append("</td>");
     html.append("<td style='padding: 10px;'>").append(dateOfRequesting).append("</td>");
     html.append("<td style='padding: 10px;'>").append(requestName).append("</td>");
     html.append("<td style='padding: 10px;'>").append(approval).append("</td>");
     html.append("<td style='padding: 10px;'>");

     html.append("<form action='accept' method='post' style='display:inline;'>");
     html.append("<input type='hidden' name='requestId' value='").append(requestId).append("' />");
     html.append("<input type='hidden' name='requestName' value='").append(requestName).append("' />");
     html.append("<input type='hidden' name='requestedFrom' value='").append(requestedFrom).append("' />");
     html.append("<button type='submit' style='padding: 6px 12px; background-color: #4CAF50; color: white; border: none; cursor: pointer;'>Accept</button>");
     html.append("</form>");

     html.append("<form action='reject' method='post' style='display:inline;'>");
     html.append("<input type='hidden' name='requestId' value='").append(requestId).append("' />");
     html.append("<button type='submit' style='padding: 6px 12px; background-color: #f44336; color: white; border: none; cursor: pointer;'>Reject</button>");
     html.append("</form>");
     
     html.append("</td>");
     html.append("</tr>");
 }
 html.append("</tbody>");
 html.append("</table>");

    return html.toString();
}



//remove users
public String removeUser(String name) throws Exception {
	String dropDown="<form action='userremove1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select An User To Delete:</label>"+
			"<select id='dropdown' name='options'>";
	Connection con=Db.connect();
	String removeuserquery="select username from user where username!=?";
	PreparedStatement pst=con.prepareStatement(removeuserquery);
	pst.setString(1,name);
	ResultSet rs=pst.executeQuery();
	while(rs.next()) {
		String value=rs.getString(1);
    	dropDown+="<option value='"+value+"'>"+value+"</option>";
	}
	dropDown+="</select>";	
    dropDown+="<button type='submit'>Submit</button>";
    dropDown+="</form>";
	return dropDown;

}

//remove user!

public String removeuser1(String options) throws Exception {
	Connection con=Db.connect();
	String removeuserquery1="delete from user where username=?";
	PreparedStatement pst1=con.prepareStatement(removeuserquery1);
	pst1.setString(1, options);
	pst1.executeUpdate();
	String removeuserquery2="delete from requests where Requestedfrom=?";
	PreparedStatement pst2=con.prepareStatement(removeuserquery2);
	pst2.setString(1, options);
	pst2.executeUpdate();
	String removeuserquery3="delete from UserResource where UserName=?";
	PreparedStatement pst3=con.prepareStatement(removeuserquery3);
	pst3.setString(1, options);
	pst3.executeUpdate();
	return "<h1>User and his all belongings are deleted</h1>";
}
   

public String resourcesremoved() throws Exception {
	String dropDown="<label for='dropdown' placeholder='Select one'>Select resourcename to delete:</label>"+
			"<select id='dropdown' name='options'>";
	Connection con=Db.connect();
	String resourcesremovedquery="select * from resources";
	PreparedStatement pst1=con.prepareStatement(resourcesremovedquery);
	ResultSet rs=pst1.executeQuery();
	while(rs.next()) {
		String value=rs.getString(1);
    	dropDown+="<option value='"+value+"'>"+value+"</option>";
	}
	dropDown+="</select>";	
    dropDown+="<button type='submit'>Submit</button>";
	return dropDown;
}

//no requestname in the db
public String resourcesremoved1(String ResourcesName) throws Exception {
	Connection con=Db.connect();
	String resourcesremovedquery1="delete from resources where ResourcesName=?";
	PreparedStatement pst1=con.prepareStatement(resourcesremovedquery1);
	pst1.setString(1, ResourcesName);
	int x=pst1.executeUpdate();
	String query2="delete from requests where requestname=?";
	PreparedStatement pst2=con.prepareStatement(query2);
	pst2.setString(1, ResourcesName);
	pst2.executeUpdate();
	String query3="delete from UserResource where Resource_Name=?";
	PreparedStatement pst3=con.prepareStatement(query3);
	pst3.setString(1, ResourcesName);
	pst3.executeUpdate();

	if(x>0) {
		return "<h1>Resource is successfully deleted<h1>";
	}
	else {
		return "There is no resource that you have entered";
	}
}

//password change in admin

public String adminpasswordchange() throws Exception {
	String s="<form action='changepassword1admin' method='post'>";
    s+="<input type='password' name='newpassword' placeholder='Enter password to change' required>";
    s+="<br>";
    s+="<input type='password' name='confirmnewpassword' placeholder='Confirm password' required>";
    s+="<button type='submit' >Submit</button>";
    s+="</form>";
    return s;	
}


public String removeresourceuser() throws Exception {
	Connection con = Db.connect();
    String query = "select * from user"; 
    PreparedStatement pst = con.prepareStatement(query);
    ResultSet rs = pst.executeQuery();
    String dropDown="<form action='removeresourcefromauser1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select A user:</label>"+
			"<select id='dropdown' name='options1'>";
    boolean hasUsers=false;
    while (rs.next()) {
    	hasUsers=true;
        String value = rs.getString("username");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!hasUsers) {
        dropDown+="<option value=''>No Users Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Show Resources</button>";
    dropDown+="</form>";
    return dropDown.toString();
}

public String removeresourceuser1(String options1) throws Exception {
	Connection con = Db.connect();
    String query = "select Resource_Name from UserResource where UserName=?";
    PreparedStatement pst = con.prepareStatement(query);
    pst.setString(1, options1);
    ResultSet rs = pst.executeQuery();
    String dropDown="<form action='removeresourcefromauser2' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select A Resource To Delete:</label>"+
			"<select id='dropdown' name='options2'>";
    boolean hasResource=false;
    while (rs.next()) {
    	hasResource=true;
        String value = rs.getString("Resource_Name");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!hasResource) {
        dropDown+="<option value='' selected disabled>No Resource Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Delete Resource</button>";
    dropDown+="</form>";
    return dropDown;
}
public String removeresourceuser2(String options2) throws Exception {
	Connection con = Db.connect();
    String query = "delete from UserResource where Resource_Name=?";
    PreparedStatement pst = con.prepareStatement(query);
    pst.setString(1, options2);
    int n=pst.executeUpdate();
    if(n>0) {
    	return "<h1>Resource is deleted successfully</h1>";
    }
    else {
    	return "<h1>Resource cannot be deleted</h1>";
    }
}

public String resourcecheckingusers() throws Exception {
	Connection c = Db.connect();
    String resourcecheckingquery = "select ResourcesName from resources";
    PreparedStatement pst = c.prepareStatement(resourcecheckingquery);
    ResultSet rs = pst.executeQuery();
    String dropDown="<label for='dropdown' placeholder='Select one'>Select A Resource To Check For Users:</label>"+
			"<select id='dropdown' name='options'>";
    boolean hasResource=false;
    while (rs.next()) {
    	hasResource=true;
        String value = rs.getString("ResourcesName");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!hasResource) {
        dropDown+="<option value=''>No Resources Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Check Users</button>";
    return dropDown;
}


public String resourcecheckinguser1(String options) throws Exception {
	Connection c=Db.connect();
	String resourcecheckinguserquery1="select * from UserResource";
	PreparedStatement pst1=c.prepareStatement(resourcecheckinguserquery1);
	ResultSet rs=pst1.executeQuery();
	boolean flag=false;
	String show="<table border='1'><tr><th>Username</th></tr>";
	while(rs.next()) {
		flag=true;
		show+="<tr>";
		show+="<td>"+rs.getString(1)+"</td>";
		show+="</tr>";
	}
	if(!flag) {
		return "<h1>No Users Available</h1>";
	}
	show+="</table>";
	return show;
}
//--->from now clear

public String checkresourcesofuser() throws Exception {
	Connection con = Db.connect();
    String ofuserquery = "select * from user";
    PreparedStatement pst=con.prepareStatement(ofuserquery);
    ResultSet rs = pst.executeQuery();
    String dropDown="<label for='dropdown' placeholder='Select one'>Select A User To Check His Resources:</label>"+
			"<select id='dropdown' name='options'>";
    boolean flag=false;
    while (rs.next()) {
    	flag=true;
        String value = rs.getString("username");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!flag) {
        dropDown+="<option value=''>No Users Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Check For Resources</button>";
    
    return dropDown;
}

public String checkresourcesofuser1(String options) throws Exception {
	Connection con=Db.connect();
	String checkresourcesofuserquery1="select Resource_Name from UserResource where UserName=?";
	PreparedStatement pst1=con.prepareStatement(checkresourcesofuserquery1);
	pst1.setString(1, options);
	ResultSet rs=pst1.executeQuery();
	String show="<table border='1'><tr><th>ResourceNames</th></tr>";
	while(rs.next()) {
		show+="<tr>";
		show+="<td>"+rs.getString("Resource_Name")+"</td>";
		show+="</tr>";
	}
	show+="</table>";
	return show;
}
public String assignresourcestoanuser() throws Exception {
	Connection c = Db.connect();
    String query = "select * from user";
    PreparedStatement pst=c.prepareStatement(query);
    ResultSet rs = pst.executeQuery();
    String dropDown="<form action='assignresourcestoanuser1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select An User To Assign Resource:</label>"+
			"<select id='dropdown' name='options1'>";
    boolean flag=false;
    while (rs.next()) {
    	flag=true;
        String value = rs.getString("username");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!flag) {
        dropDown+="<option value=''>No Users Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Check For Unavailable Resources</button>";
    dropDown+="</form>";
    return dropDown;
}
public String assignresourcestoanuser1(String options1) throws Exception {
	Connection c = Db.connect();
    String query1 = "select Resource_Name from UserResource where UserName=?";
    PreparedStatement pst1 = c.prepareStatement(query1);
    pst1.setString(1, options1);
    ResultSet rs1= pst1.executeQuery();
    Set<String> hs = new HashSet<>();
    while (rs1.next()) {
        hs.add(rs1.getString(1));
    }
    String query2 = "select RequestName from requests where Requestedfrom=? and ApprovalStatus='pending'";
    PreparedStatement pst2 = c.prepareStatement(query2);
    pst2.setString(1, options1);
    ResultSet rs2= pst2.executeQuery();
    Set<String> hs2 = new HashSet<>();
    while (rs2.next()) {
        hs2.add(rs2.getString(1));
    }
    String query3 = "select ResourcesName from resources";
    PreparedStatement pst3 = c.prepareStatement(query3);
    ResultSet rs3 = pst3.executeQuery();
    StringBuilder dropDown = new StringBuilder("<form action='assignresourcestoanuser2' method='post'>");
    dropDown.append("<label for='dropdown' placeholder='Select one'>Select resource name to request:</label>");
    dropDown.append("<select id='dropdown' name='options2'>");
    boolean hasAvailableResources = false;
    while (rs3.next()) {
        String resourceName = rs3.getString(1);
        if (!hs.contains(resourceName) && !hs2.contains(resourceName)) {
            dropDown.append("<option value='").append(resourceName).append("'>").append(resourceName).append("</option>");
            hasAvailableResources = true;
        }
    }
    if (!hasAvailableResources) {
        dropDown.append("<option value=''>No resources available</option>");
    }
    dropDown.append("</select>");
    dropDown.append("<input type='hidden' name='options1' value='").append(options1).append("'>");
    dropDown.append("<button type='submit'>Assign</button>");
    dropDown.append("</form>");
    return dropDown.toString();
}
public String assignresourcestoanuser2(String options1, String options2) throws Exception {
    Connection c = Db.connect();
    
    // Check if the resource is already assigned to the user
    String checkQuery = "select count(*) from UserResource where UserName=? and Resource_Name=?";
    PreparedStatement checkPst = c.prepareStatement(checkQuery);
    checkPst.setString(1, options1);
    checkPst.setString(2, options2);
    ResultSet rs = checkPst.executeQuery();
    rs.next();
    int count = rs.getInt(1);
    
    if (count > 0) {
        return "<h1>This resource is already assigned to the user.</h1>";
    }
    
    // Proceed with the assignment if no duplicates are found
    String query = "insert into UserResource (UserName, Resource_Name) values(?, ?)";
    PreparedStatement pst = c.prepareStatement(query);
    pst.setString(1, options1);
    pst.setString(2, options2);
    pst.executeUpdate();
    
    return "<h1>Resource is Assigned Successfully</h1>";
}


public String makeasadminormanager() throws Exception {
    Connection c = Db.connect();
    String query = "select username from user where usertype !='admin'";
    PreparedStatement pst = c.prepareStatement(query);
    ResultSet rs = pst.executeQuery();

    StringBuilder dropDown = new StringBuilder("<form action='makeasadminormanager1' method='post'>");
    dropDown.append("<label for='dropdown'>Select a User to Change User Type:</label>");
    dropDown.append("<select id='dropdown' name='options1'>");

    boolean flag = false;
    while (rs.next()) {
        flag = true;
        String value = rs.getString("username");
        if (value != null && !value.isEmpty()) {
            dropDown.append("<option value='").append(value).append("'>").append(value).append("</option>");
        }
    }

    if (!flag) {
        dropDown.append("<option value=''>No Users Available</option>");
    }

    dropDown.append("</select>");
    dropDown.append("<button type='submit'>Check User Type</button>");
    dropDown.append("</form>");

    return dropDown.toString();
}

public String makeasadminormanager1(String options1) throws Exception {
    if (options1 == null || options1.isEmpty()) {
        return "<h1>No valid user selected.</h1>";
    }

    Connection c = Db.connect();
    String query1 = "select usertype from user where username=? and usertype !='admin'";
    PreparedStatement pst1 = c.prepareStatement(query1);
    pst1.setString(1, options1);
    ResultSet rs = pst1.executeQuery();

    String typeofuser = null;
    if (rs.next()) {
        typeofuser = rs.getString("usertype");
    }

    StringBuilder dropDown = new StringBuilder("<form action='makeasadminormanager2' method='post'>");
    dropDown.append("<label for='dropdown'>Select New User Type:</label>");
    dropDown.append("<select id='dropdown' name='options2'>");

    if (typeofuser != null) {
        switch (typeofuser) {
            case "user":
                dropDown.append("<option value='Admin'>Admin</option>");
                dropDown.append("<option value='Manager'>Manager</option>");
                break;
            case "manager":
                dropDown.append("<option value='User'>User</option>");
                dropDown.append("<option value='Admin'>Admin</option>");
                break;
            case "admin":
                dropDown.append("<option value='User'>User</option>");
                dropDown.append("<option value='Manager'>Manager</option>");
                break;
            default:
                dropDown.append("<option value=''>Invalid user type found</option>");
                break;
        }
    } else {
        dropDown.append("<option value=''>No user type found</option>");
    }

    dropDown.append("</select>");
    dropDown.append("<input type='hidden' name='options1' value='").append(options1).append("'>");
    dropDown.append("<button type='submit'>Change User Type</button>");
    dropDown.append("</form>");

    return dropDown.toString();
}
public String makeasadminormanager2(String options1, String options2) throws Exception {
    if (options1 == null || options1.isEmpty() || options2 == null || options2.isEmpty()) {
        return "<h1>Invalid input. Please select a valid user and user type.</h1>";
    }

    Connection c = Db.connect();
    String query1 = "update user set usertype=? where username=?";
    PreparedStatement pst = c.prepareStatement(query1);
    pst.setString(1, options2);
    pst.setString(2, options1);
    int updatedRows = pst.executeUpdate();

    if (updatedRows > 0) {
        return "<h1>User type updated successfully to " + options2 + ".</h1>";
    } else {
        return "<h1>Failed to update user type. Please try again.</h1>";
    }
}


//admin over


//manager start
public String teamList(String name) throws Exception {
	Connection con=Db.connect();
	String teamListquery="select * from user where managername=?";
	PreparedStatement pst=con.prepareStatement(teamListquery);
	pst.setString(1, name);
	ResultSet rs=pst.executeQuery();
	String show="<table border='1'><tr><th>UserName</th><th>UserType</th><th>DateOfJoined</th></tr>";
	while(rs.next()) {
		show+="<tr>";
		show+="<td>"+rs.getString("username")+"</td>";
		show+="<td>"+rs.getString("usertype")+"</td>";
		show+="<td>"+rs.getString("doj")+"</td>";
		show+="</tr>";
	}
	show+="</table>";
	return show;

}
public String getteammember() throws Exception {
	Connection con=Db.connect();
	String getteammemberquery="select username from user where usertype=? and managername is null";
	PreparedStatement pst=con.prepareStatement(getteammemberquery);
	pst.setString(1,"User");//why user
	ResultSet rs=pst.executeQuery();
	String dropDown="<form action='togetateammember1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select A User To Add Into Your Team</label>"+
			"<select id='dropdown' name='options'>";
    boolean flag=false;
    while (rs.next()) {
    	flag=true;
        String value = rs.getString("username");
        dropDown+="<option value='"+value+"'>"+value+"</option>";
    }
    if (!flag) {
        dropDown+="<option value=''>No Users Available</option>";
    }
    dropDown+="</select>";	
    dropDown+="<button type='submit'>Add To Team</button>";
    dropDown+="</form>";
    return dropDown;
}


public String getteammember1(String options,String name) throws Exception {
	Connection con=Db.connect();
	String getteammemberquery="update user set managername=? where username=?";
	PreparedStatement pst=con.prepareStatement(getteammemberquery);
	pst.setString(1,name);
	pst.setString(2,options);
	pst.executeUpdate();
	return "<h1>User Added to Your Team</h1>";
}


public String requestresourcesmanager(String name) throws Exception {
    Connection con = Db.connect();
    String requestresourcesmanagerquery1 = "select Resource_Name from UserResource where UserName=?";
    PreparedStatement pst1 = con.prepareStatement(requestresourcesmanagerquery1);
    pst1.setString(1, name);
    ResultSet rs1= pst1.executeQuery();
    Set<String> hs = new HashSet<>();
    while (rs1.next()) {
        hs.add(rs1.getString(1));
    }
    String query2 = "select requestname from requests where Requestedfrom=? and ApprovalStatus='pending'";
    PreparedStatement pst2 = con.prepareStatement(query2);
    pst2.setString(1, name);
    ResultSet rs2= pst2.executeQuery();
    Set<String> hs2 = new HashSet<>();
    while (rs2.next()) {
        hs2.add(rs2.getString(1));
    }
    String query3 = "select ResourcesName from resources";
    PreparedStatement pst3 = con.prepareStatement(query3);
    ResultSet rs3 = pst3.executeQuery();
    StringBuilder dropDown = new StringBuilder("<form action='requestaboutresourcesmanage1' method='post'>");
    dropDown.append("<label for='dropdown' placeholder='Select one'>Select resource name to request:</label>");
    dropDown.append("<select id='dropdown' name='options'>");
    boolean hasAvailableResources = false;
    while (rs3.next()) {
        String resourceName = rs3.getString(1);
        if (!hs.contains(resourceName) && !hs2.contains(resourceName)) {
            dropDown.append("<option value='").append(resourceName).append("'>").append(resourceName).append("</option>");
            hasAvailableResources = true;
        }
    }
    if (!hasAvailableResources) {
        dropDown.append("<option value=''>No resources available</option>");
    }
    dropDown.append("</select>");
    dropDown.append("<button type='submit'>Submit</button>");
    dropDown.append("</form>");
    return dropDown.toString();
}

public String requestresourcemanager1(String options,String s) throws Exception {
	Connection con=Db.connect();
	String requestresourcemanagerquery1="SELECT COUNT(*) FROM requests";
	PreparedStatement pst1=con.prepareStatement(requestresourcemanagerquery1);
	ResultSet rs1=pst1.executeQuery();
	int count=0;
	String query2="insert into requests(RequestId,Requestedfrom,DOR,ApprovalStatus,requestname,requesteetype) values (?,?,?,?,?,?)";
	PreparedStatement pst2=con.prepareStatement(query2);
	if(rs1.next()) {
		String query3="SELECT max(RequestId) FROM requests";
		PreparedStatement pst3=con.prepareStatement(query3);
		ResultSet rs3=pst3.executeQuery();
		if(rs3.next()) {
			count=rs3.getInt(1);
		}
	}
	pst2.setInt(1,count+1);
	pst2.setString(2, s);
	LocalDate date=LocalDate.now();
	pst2.setString(3, date.toString());
	pst2.setString(4, "pending");
	pst2.setString(5, options);
	pst2.setString(6, "Manager");
	pst2.executeUpdate();
	return "Resource is requested";
}
//---> check form removeresources1manager
public String removeownresourcesmanager(String uname) throws Exception {
	Connection con=Db.connect();
	String removeownresourcesmanagerquery="select Resource_Name from UserResource where UserName=?";
	PreparedStatement pst=con.prepareStatement(removeownresourcesmanagerquery);
	pst.setString(1, uname);
	ResultSet rs=pst.executeQuery();
	String dropDown="<form action='removingresourcesformanage1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select resourcename to delete:</label>"+
			"<select id='dropdown' name='options'>";
	while(rs.next()) {
		String value=rs.getString(1);
    	dropDown+="<option value='"+value+"'>"+value+"</option>";
	}
	if(!rs.next()) {
		dropDown+="<option value=''>No options available</option>";
	}
	dropDown+="</select>";	
    dropDown+="<button type='submit'>Submit</button>";
    dropDown+="</form>";
	return dropDown;
}

public String requestingformanager(String options,String s) throws Exception {
	Connection con=Db.connect();
	String requestingformanagerquery="SELECT COUNT(*) FROM requests";
	PreparedStatement pst1=con.prepareStatement(requestingformanagerquery);
	ResultSet rs=pst1.executeQuery();
	int count=0;
	String requestingformanagerquery2="insert into requests(RequestId,Requestedfrom,DOR,ApprovalStatus,requestname,requesteetype) values (?,?,?,?,?,?)";
	PreparedStatement pst2=con.prepareStatement(requestingformanagerquery2);
	if(rs.next()) {
		count=Integer.parseInt(rs.getString(1));
	}
	pst2.setInt(1,count+1);
	pst2.setString(2, s);
	LocalDate date=LocalDate.now();
	pst2.setString(3, date.toString());
	pst2.setString(4, "pending");
	pst2.setString(5, options);
	pst2.setString(6, "Manager");
	pst2.executeUpdate();
	return "Resource is requested";
}


//user funcctions


public String requestingforresources(String name) throws Exception {
    Connection con = Db.connect();
    String requestingforresourcesquery1 = "select Resource_Name from UserResource where UserName=?";
    PreparedStatement pst1 = con.prepareStatement(requestingforresourcesquery1);
    pst1.setString(1, name);
    ResultSet rs1= pst1.executeQuery();
    Set<String> hs = new HashSet<>();
    while (rs1.next()) {
        hs.add(rs1.getString(1));
    }
    String requestingforresourcesquery2 = "select RequestName  from requests where Requestedfrom=? and ApprovalStatus='pending'";
    PreparedStatement pst2 = con.prepareStatement(requestingforresourcesquery2);
    pst2.setString(1, name);
    ResultSet rs2= pst2.executeQuery();
    Set<String> hs2 = new HashSet<>();
    while (rs2.next()) {
        hs2.add(rs2.getString(1));
    }
    String requestingforresourcesquery3 = "select ResourcesName from resources";
    PreparedStatement pst3 = con.prepareStatement(requestingforresourcesquery3);
    ResultSet rs3 = pst3.executeQuery();
    StringBuilder dropDown = new StringBuilder("<form action='resourcesarerequested1' method='post'>");
    dropDown.append("<label for='dropdown' placeholder='Select one'>Select resource name to request:</label>");
    dropDown.append("<select id='dropdown' name='options'>");
    boolean hasAvailableResources = false;
    while (rs3.next()) {
        String resourceName = rs3.getString(1);
        if (!hs.contains(resourceName) && !hs2.contains(resourceName)) {
            dropDown.append("<option value='").append(resourceName).append("'>").append(resourceName).append("</option>");
            hasAvailableResources = true;
        }
    }
    if (!hasAvailableResources) {
        dropDown.append("<option value='' selected disabled >No resources available</option>");
    }
    dropDown.append("</select>");
    dropDown.append("<input type='submit'>");
    dropDown.append("</form>");
    return dropDown.toString();
}

public String requestingforresource1(String options,String s) throws Exception {
	Connection con=Db.connect();
	String query1="SELECT COUNT(*) FROM requests";
	PreparedStatement pst1=con.prepareStatement(query1);
	ResultSet rs1=pst1.executeQuery();
	int count=0;
	String query2="insert into requests(RequestId,Requestedfrom,DOR,ApprovalStatus,requestname,requesteetype) values (?,?,?,?,?,?)";
	PreparedStatement pst2=con.prepareStatement(query2);
	if(rs1.next()) {
		String query3="SELECT max(RequestId) FROM requests";
		PreparedStatement pst3=con.prepareStatement(query3);
		ResultSet rs3=pst3.executeQuery();
		if(rs3.next()) {
			count=rs3.getInt(1);
		}
	}
	pst2.setInt(1,count+1);
	pst2.setString(2, s);
	LocalDate date=LocalDate.now();
	pst2.setString(3, date.toString());
	pst2.setString(4, "pending");
	pst2.setString(5, options);
	pst2.setString(6, "User");
	pst2.executeUpdate();
	return "Resource is requested";
}

public String checkforapprovals(String uname) throws Exception {
	Connection con=Db.connect();
	String query="select * from requests where Requestedfrom=?";
	PreparedStatement pst=con.prepareStatement(query);
	pst.setString(1, uname);
	ResultSet rs=pst.executeQuery();
	String List = "<table border='1' style='border-collapse: collapse; width: 100%;'>";
	List += "<tr style='background-color: #f2f2f2;'>";
	List += "<th style='padding: 8px; text-align: left;'>RequestId</th>";
	List += "<th style='padding: 8px; text-align: left;'>DateOfRequesting</th>";
	List += "<th style='padding: 8px; text-align: left;'>RequestName</th>";
	List += "<th style='padding: 8px; text-align: left;'>ApprovalStatus</th>";
	List += "</tr>";

	while(rs.next()) {
	    List += "<tr style='border-bottom: 1px solid #ddd;'>";
	    List += "<td style='padding: 8px;'>" + rs.getInt(1) + "</td>";
	    List += "<td style='padding: 8px;'>" + rs.getString(3) + "</td>";
	    List += "<td style='padding: 8px;'>" + rs.getString(5) + "</td>";
	    List += "<td style='padding: 8px;'>" + rs.getString(4) + "</td>";
	    List += "</tr>";
	}

	List += "</table>";

	return List;
}

public String myresources(String uname) throws Exception {
	Connection con=Db.connect();
	String myresourcesquery="select Resource_Name from UserResource where UserName=?";
	PreparedStatement pst=con.prepareStatement(myresourcesquery);
	pst.setString(1, uname);
	ResultSet rs=pst.executeQuery();
	String List="<table border='1'><tr><th>MyResoures</th></tr>";
	while(rs.next()) {
		List+="<tr>";
		List+="<td>"+rs.getString("Resource_Name")+"</td>";
		List+="</tr>";
	}
	List+="</table>";
	return List;
}

public String removeourresource(String uname) throws Exception {
	Connection con=Db.connect();
	String query="select Resource_Name from UserResource where UserName=?";
	PreparedStatement pst=con.prepareStatement(query);
	pst.setString(1, uname);
	ResultSet rs=pst.executeQuery();
	String dropDown="<form action='removingresourcesformanage1' method='post'>"+"<label for='dropdown' placeholder='Select one'>Select resourcename to delete:</label>"+
			"<select id='dropdown' name='options'>";
	while(rs.next()) {
		String value=rs.getString(1);
    	dropDown+="<option value='"+value+"'>"+value+"</option>";
	}
	if(!rs.next()) {
		dropDown+="<option value='' selected disabled >No options available</option>";
	}
	dropDown+="</select>";	
    dropDown+="<button type='submit'>Submit</button>";
    dropDown+="</form>";
	return dropDown;
}

public String removingresource1(String option) throws Exception {
	Connection con=Db.connect();
	String query="delete from UserResource where Resource_Name=?";
	PreparedStatement pst=con.prepareStatement(query);
	pst.setString(1, option);
	pst.executeUpdate();
	return "Resource is removed successfully";
}

public String requestingfor(String uname) throws Exception {
	Connection con = Db.connect();
    String queryAdmin = "SELECT 1 FROM requests WHERE Requestedfrom=? AND RequestName=?";
    String queryManager = "SELECT 1 FROM requests WHERE Requestedfrom=? AND RequestName=?";
    PreparedStatement pstAdmin = con.prepareStatement(queryAdmin);
    pstAdmin.setString(1, uname);
    pstAdmin.setString(2, "Admin");
    ResultSet rsAdmin = pstAdmin.executeQuery();
    PreparedStatement pstManager = con.prepareStatement(queryManager);
    pstManager.setString(1, uname);
    pstManager.setString(2, "Manager");
    ResultSet rsManager = pstManager.executeQuery();
    StringBuilder dropDown = new StringBuilder("<form action='requestingfor1' method='post'>");
    dropDown.append("<label for='dropdown' placeholder='Select one'>Select resource name to request:</label>");
    dropDown.append("<select id='dropdown' name='options'>");
    boolean adminRequested = rsAdmin.next();
    boolean managerRequested = rsManager.next();
    if (adminRequested && managerRequested) {
        dropDown.append("<option value=''>No options available</option>");
    } else if (!adminRequested && !managerRequested) {
        dropDown.append("<option value='Admin'>Admin</option>");
        dropDown.append("<option value='Manager'>Manager</option>");
    } else if (adminRequested) {
        dropDown.append("<option value='Manager'>Manager</option>");
    } else if (managerRequested) {
        dropDown.append("<option value='Admin'>Admin</option>");
    }
    dropDown.append("</select>");
    dropDown.append("<button type='submit'>Submit</button>");
    dropDown.append("</form>");
    return dropDown.toString();
}


public String requestingfor1(String options,String s) throws Exception {
	Connection c=Db.connect();
	String query1="SELECT COUNT(*) FROM requests";
	PreparedStatement pst1=c.prepareStatement(query1);
	ResultSet rs1=pst1.executeQuery();
	int count=0;
	String query2="insert into requests(RequestId,Requestedfrom,DOR,ApprovalStatus,requestname,requesteetype) values (?,?,?,?,?,?)";
	PreparedStatement pst2=c.prepareStatement(query2);
	if(rs1.next()) {
		count=Integer.parseInt(rs1.getString(1));
	}
	pst2.setInt(1,count+1);
	pst2.setString(2, s);
	LocalDate date=LocalDate.now();
	pst2.setString(3, date.toString());
	pst2.setString(4, "pending");
	pst2.setString(5, options);
	pst2.setString(6, "User");
	pst2.executeUpdate();
	return "Resource is requested";
} 
public String changepassword() throws Exception {
	String s="<form action='changepassword1' method='post'>";
    s+="<input type='password' name='newpassword' placeholder='Enter password to change' required>";
    s+="<br>";
    s+="<input type='password' name='confirmnewpassword' placeholder='Confirm password' required>";
    s+="<button type='submit' >Submit</button>";
    s+="</form>";
    return s;	
}

public String changepassword1(String name,String p) throws Exception {
	Connection con=Db.connect();
	String query="update user set pwd=? where username=?";
	PreparedStatement pst=con.prepareStatement(query);
	pst.setString(1, encrypt(p));
	pst.setString(2, name);
	pst.executeUpdate();
	return "<h1>Password successfully updated.</h1>";
}
}



