/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE400_Resource_Exhaustion__database_write_01.java
Label Definition File: CWE400_Resource_Exhaustion.label.xml
Template File: sources-sinks-01.tmpl.java
*/
/*
* @description
* CWE: 400 Resource Exhaustion
* BadSource: database Read count from a database
* GoodSource: A hardcoded non-zero, non-min, non-max, even number
* Sinks: write
*    GoodSink: Write to a file count number of times, but first validate count
*    BadSink : Write to a file count number of times
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE400_Resource_Exhaustion;

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

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.io.IOException;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE400_Resource_Exhaustion__database_write_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {
        int count;

        count = Integer.MIN_VALUE; /* Initialize count */

        /* Read count from a database */
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

                /* POTENTIAL FLAW: Read count from a database query resultset */
                String s_count = rs.getString(1);
                if (s_count != null)   // avoid NPD incidental warnings
                {
                    try
                    {
                        count = Integer.parseInt(s_count.trim());
                    }
                    catch(NumberFormatException nfe)
                    {
                        IO.logger.log(Level.WARNING, "Number format exception parsing count from string", nfe);
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

        File file = new File("badSink.txt");
        FileOutputStream fos = new FileOutputStream(file);
        OutputStreamWriter oswrite = new OutputStreamWriter(fos, "UTF-8");
        BufferedWriter buffwrite = new BufferedWriter(oswrite);
        int i;

        /* POTENTIAL FLAW: Do not validate count before using it as the for loop variant to write to a file */
        for (i = 0; i < count; i++)
        {
            try
            {
                buffwrite.write("Hello");
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error with stream writing", ioe);
            }
        }

        /* Close stream reading objects */
        try
        {
            if( buffwrite != null )
            {
                buffwrite.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing BufferedWriter", ioe);
        }

        try
        {
            if( oswrite != null )
            {
                oswrite.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing OutputStreamWriter", ioe);
        }

        try
        {
            if( fos != null )
            {
                fos.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing FileOutputStream", ioe);
        }

    }

    public void good() throws Throwable
    {
        goodG2B();
        goodB2G();
    }

    /* goodG2B() - use goodsource and badsink */
    private void goodG2B() throws Throwable
    {
        int count;

        /* FIX: Use a hardcoded number that won't cause underflow, overflow, divide by zero, or loss-of-precision issues */
        count = 2;

        File file = new File("badSink.txt");
        FileOutputStream fos = new FileOutputStream(file);
        OutputStreamWriter oswrite = new OutputStreamWriter(fos, "UTF-8");
        BufferedWriter buffwrite = new BufferedWriter(oswrite);
        int i;

        /* POTENTIAL FLAW: Do not validate count before using it as the for loop variant to write to a file */
        for (i = 0; i < count; i++)
        {
            try
            {
                buffwrite.write("Hello");
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error with stream writing", ioe);
            }
        }

        /* Close stream reading objects */
        try
        {
            if( buffwrite != null )
            {
                buffwrite.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing BufferedWriter", ioe);
        }

        try
        {
            if( oswrite != null )
            {
                oswrite.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing OutputStreamWriter", ioe);
        }

        try
        {
            if( fos != null )
            {
                fos.close();
            }
        }
        catch( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error closing FileOutputStream", ioe);
        }

    }

    /* goodB2G() - use badsource and goodsink */
    private void goodB2G() throws Throwable
    {
        int count;

        count = Integer.MIN_VALUE; /* Initialize count */

        /* Read count from a database */
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

                /* POTENTIAL FLAW: Read count from a database query resultset */
                String s_count = rs.getString(1);
                if (s_count != null)   // avoid NPD incidental warnings
                {
                    try
                    {
                        count = Integer.parseInt(s_count.trim());
                    }
                    catch(NumberFormatException nfe)
                    {
                        IO.logger.log(Level.WARNING, "Number format exception parsing count from string", nfe);
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

        /* FIX: Validate count before using it as the for loop variant to write to a file */
        if (count > 0 && count <= 20)
        {
            File file = new File("goodSink.txt");
            FileOutputStream fos = new FileOutputStream(file);
            OutputStreamWriter oswrite = new OutputStreamWriter(fos, "UTF-8");
            BufferedWriter buffwrite = new BufferedWriter(oswrite);
            int i;
            for (i = 0; i < count; i++)
            {
                try
                {
                    buffwrite.write("Hello");
                }
                catch (IOException ioe)
                {
                    IO.logger.log(Level.WARNING, "Error with stream writing", ioe);
                }
            }
            /* Close stream reading objects */
            try
            {
                if( buffwrite != null )
                {
                    buffwrite.close();
                }
            }
            catch( IOException ioe )
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedWriter", ioe);
            }
            try
            {
                if( oswrite != null )
                {
                    oswrite.close();
                }
            }
            catch( IOException ioe )
            {
                IO.logger.log(Level.WARNING, "Error closing OutputStreamWriter", ioe);
            }
            try
            {
                if( fos != null )
                {
                    fos.close();
                }
            }
            catch( IOException ioe )
            {
                IO.logger.log(Level.WARNING, "Error closing FileOutputStream", ioe);
            }
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

