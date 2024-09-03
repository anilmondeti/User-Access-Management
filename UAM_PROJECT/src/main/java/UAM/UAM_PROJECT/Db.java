package UAM.UAM_PROJECT;

import java.sql.Connection;
import java.sql.DriverManager;


public class Db {
	
	public static Connection connect() throws Exception {
		String driver="com.mysql.cj.jdbc.Driver", url="jdbc:mysql://localhost:3306/usermanagment", userName="root",password="root";
		Class.forName(driver);
		Connection c=DriverManager.getConnection(url, userName, password);
		return c;
		
	}

	
}

