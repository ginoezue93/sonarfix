/*
 * @description Missing Release of Resource After Effective Lifetime.  Performs some, but not all, necessary resource cleanup (DB connection is not closed).
 * 
 * */

package testcases.CWE772_Missing_Release_of_Resource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.io.*;
import java.security.SecureRandom;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE772_Missing_Release_of_Resource__db_Connection_01 extends
		AbstractTestCase 
{
    public void bad()
	{
		ResultSet rs = null;
		Connection conn = null;
		PreparedStatement statement = null;

        try
        {
            int num = (new SecureRandom()).nextInt(200);

            conn = IO.getDBConnection();
            statement = conn.prepareStatement("select * from users where id=?");
            statement.setInt(1, num);
            
            rs = statement.executeQuery();
            
            if (rs.first())
            {
                IO.writeString(rs.toString());
            }
        }
		catch(SQLFeatureNotSupportedException sfnse)
        {
            IO.logger.log(Level.WARNING, "SQL feature not supported", sfnse);
        }
        catch(SQLException e)
        {
            IO.logger.log(Level.WARNING, "Error!", e);
        }
		
		/* FLAW: DB objects are never closed */
		
	}

	private void good1()
	{
		ResultSet rs = null;
		Connection conn = null;
		PreparedStatement statement = null;

        try
        {
            int num = (new SecureRandom()).nextInt(200);

            conn = IO.getDBConnection();
            statement = conn.prepareStatement("select * from users where id=?");
            statement.setInt(1, num);
            
            rs = statement.executeQuery();
            
            if (rs.first())
            {
                IO.writeString(rs.toString());
            }
        }
		catch(SQLFeatureNotSupportedException sfnse)
        {
            IO.logger.log(Level.WARNING, "SQL feature not supported", sfnse);
        }
        catch(SQLException e)
        {
            IO.logger.log(Level.WARNING, "Error!", e);
        }
        finally
		/* FIX: Closing DB objects */
        {
            try
            {
                if( rs != null )
                {
                    rs.close();
                }
            }
            catch(SQLException e)
            {
                IO.logger.log(Level.WARNING, "Error closing ResultSet", e);
            }
            
			try
			{
				if( statement != null )
				{
					statement.close();
				}
			}
			catch(SQLException e)
			{
				IO.logger.log(Level.WARNING, "Error closing PreparedStatement", e);
			}
			
			try
			{
				if (conn != null)
				{
					conn.close();
				}
			}
			catch(SQLException e )
			{
				IO.logger.log(Level.WARNING, "Error closing Connection", e);
			}
        }
	}
	
	public void good() throws IOException, SQLException 
	{
        good1();
    }
	
	/* Below is the main(). It is only used when building this testcase on 
	   its own for testing or for building a binary to use in testing binary 
	   analysis tools. It is not used when compiling all the testcases as one 
	   application, which is how source code analysis tools are tested. */ 
	public static void main(String[] args) throws ClassNotFoundException,
			InstantiationException, IllegalAccessException {
		mainFromParent(args);
    }
}
