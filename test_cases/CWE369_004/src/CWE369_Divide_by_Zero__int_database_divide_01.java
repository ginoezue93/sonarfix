/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__int_database_divide_01.java
Label Definition File: CWE369_Divide_by_Zero__int.label.xml
Template File: sources-sinks-01.tmpl.java
*/
/*
* @description
* CWE: 369 Divide by zero
* BadSource: database Read data from a database
* GoodSource: A hardcoded non-zero, non-min, non-max, even number
* Sinks: divide
*    GoodSink: Check for zero before dividing
*    BadSink : Dividing by a value that may be zero
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE369_Divide_by_Zero;

import testcasesupport.*;

import java.sql.*;
import javax.servlet.http.*;
import java.security.SecureRandom;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE369_Divide_by_Zero__int_database_divide_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {
        int data;

        data = Integer.MIN_VALUE; /* Initialize data */

        /* Read data from a database */
        {
            Connection conn = null;
            PreparedStatement statement = null;
            ResultSet rs = null;
            try {
                /* setup the connection */
                conn = IO.getDBConnection();

                /* prepare and execute a (hardcoded) query */
                statement = conn.prepareStatement("select name from users where id=0");
                rs = statement.executeQuery();

                /* POTENTIAL FLAW: Read data from a database query resultset */
                String s_data = rs.getString(1);
                if (s_data != null)   // avoid NPD incidental warnings
                {
                    try
                    {
                        data = Integer.parseInt(s_data.trim());
                    }
                    catch(NumberFormatException nfe)
                    {
                        IO.logger.log(Level.WARNING, "Number format exception parsing data from string", nfe);
                    }
                }
            }
            catch( SQLException se )
            {
                IO.logger.log(Level.WARNING, "Error with SQL statement", se);
            }
            finally {
                /* Close database objects */
                try {
                    if( rs != null )
                    {
                        rs.close();
                    }
                }
                catch( SQLException se )
                {
                    IO.logger.log(Level.WARNING, "Error closing ResultSet", se);
                }

                try {
                    if( statement != null )
                    {
                        statement.close();
                    }
                }
                catch( SQLException se )
                {
                    IO.logger.log(Level.WARNING, "Error closing Statement", se);
                }

                try {
                    if( conn != null )
                    {
                        conn.close();
                    }
                }
                catch( SQLException se)
                {
                    IO.logger.log(Level.WARNING, "Error closing Connection", se);
                }
            }
        }

        /* POTENTIAL FLAW: Zero denominator will cause an issue.  An integer division will
        result in an exception. */
        IO.writeLine("bad: 100/" + String.valueOf(data) + " = " + (100 / data) + "\n");

    }

    public void good() throws Throwable
    {
        goodG2B();
        goodB2G();
    }

    /* goodG2B() - use goodsource and badsink */
    private void goodG2B() throws Throwable
    {
        int data;

        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        data = 2;

        /* POTENTIAL FLAW: Zero denominator will cause an issue.  An integer division will
        result in an exception. */
        IO.writeLine("bad: 100/" + String.valueOf(data) + " = " + (100 / data) + "\n");

    }

    /* goodB2G() - use badsource and goodsink */
    private void goodB2G() throws Throwable
    {
        int data;

        data = Integer.MIN_VALUE; /* Initialize data */

        /* Read data from a database */
        {
            Connection conn = null;
            PreparedStatement statement = null;
            ResultSet rs = null;
            try {
                /* setup the connection */
                conn = IO.getDBConnection();

                /* prepare and execute a (hardcoded) query */
                statement = conn.prepareStatement("select name from users where id=0");
                rs = statement.executeQuery();

                /* POTENTIAL FLAW: Read data from a database query resultset */
                String s_data = rs.getString(1);
                if (s_data != null)   // avoid NPD incidental warnings
                {
                    try
                    {
                        data = Integer.parseInt(s_data.trim());
                    }
                    catch(NumberFormatException nfe)
                    {
                        IO.logger.log(Level.WARNING, "Number format exception parsing data from string", nfe);
                    }
                }
            }
            catch( SQLException se )
            {
                IO.logger.log(Level.WARNING, "Error with SQL statement", se);
            }
            finally {
                /* Close database objects */
                try {
                    if( rs != null )
                    {
                        rs.close();
                    }
                }
                catch( SQLException se )
                {
                    IO.logger.log(Level.WARNING, "Error closing ResultSet", se);
                }

                try {
                    if( statement != null )
                    {
                        statement.close();
                    }
                }
                catch( SQLException se )
                {
                    IO.logger.log(Level.WARNING, "Error closing Statement", se);
                }

                try {
                    if( conn != null )
                    {
                        conn.close();
                    }
                }
                catch( SQLException se)
                {
                    IO.logger.log(Level.WARNING, "Error closing Connection", se);
                }
            }
        }

        /* FIX: test for a zero denominator */
        if( data != 0 )
        {
            IO.writeLine("100/" + String.valueOf(data) + " = " + (100 / data) + "\n");
        }
        else
        {
            IO.writeLine("This would result in a divide by zero");
        }

    }

    /* Below is the main(). It is only used when building this testcase on
       its own for testing or for building a binary to use in testing binary
       analysis tools. It is not used when compiling all the testcases as one
       application, which is how source code analysis tools are tested. */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
        mainFromParent(args);
    }
}

