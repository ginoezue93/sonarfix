/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE643_Xpath_Injection__database_01.java
Label Definition File: CWE643_Xpath_Injection.label.xml
Template File: sources-sinks-01.tmpl.java
*/
/*
* @description
* CWE: 643 Xpath Injection
* BadSource: database Read data from a database
* GoodSource: A hardcoded string
* Sinks: unvalidatedXPath
*    GoodSink: validate input through StringEscapeUtils
*    BadSink : user input is used without validate
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE643_Xpath_Injection;

import testcasesupport.*;

import java.io.*;
import javax.xml.xpath.*;
import javax.servlet.http.*;

import org.xml.sax.InputSource;

import org.apache.commons.lang.StringEscapeUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE643_Xpath_Injection__database_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {
        String data;

        data = ""; /* Initialize data */

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
                data = rs.getString(1);
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

        final String xmldoc = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";

        if (data != null)
        {
            /* assume username||password as source */
            String [] tokens = data.split("||");
            if( tokens.length < 2 )
            {
                return;
            }
            String uname = tokens[0];
            String pword = tokens[1];
            /* build xpath */
            XPath xp = XPathFactory.newInstance().newXPath();
            InputSource inxml = new InputSource(xmldoc);
            /* INCIDENTAL: CWE180 Incorrect Behavior Order: Validate Before Canonicalize
             * 	The user input should be canonicalized before validation.
             */
            /* POTENTIAL FLAW: user input is used without validate */
            String query = "//users/user[name/text()='" + uname +
                           "' and pass/text()='" + pword + "']" +
                           "/secret/text()";
            String secret = (String)xp.evaluate(query, inxml, XPathConstants.STRING);
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
        String data;

        /* FIX: Use a hardcoded string */
        data = "foo";

        final String xmldoc = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";

        if (data != null)
        {
            /* assume username||password as source */
            String [] tokens = data.split("||");
            if( tokens.length < 2 )
            {
                return;
            }
            String uname = tokens[0];
            String pword = tokens[1];
            /* build xpath */
            XPath xp = XPathFactory.newInstance().newXPath();
            InputSource inxml = new InputSource(xmldoc);
            /* INCIDENTAL: CWE180 Incorrect Behavior Order: Validate Before Canonicalize
             * 	The user input should be canonicalized before validation.
             */
            /* POTENTIAL FLAW: user input is used without validate */
            String query = "//users/user[name/text()='" + uname +
            "' and pass/text()='" + pword + "']" +
            "/secret/text()";
            String secret = (String)xp.evaluate(query, inxml, XPathConstants.STRING);
        }

    }

    /* goodB2G() - use badsource and goodsink */
    private void goodB2G() throws Throwable
    {
        String data;

        data = ""; /* Initialize data */

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
                data = rs.getString(1);
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

        final String xmldoc = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";

        if (data != null)
        {
            /* assume username||password as source */
            String [] tokens = data.split("||");
            if( tokens.length < 2 )
            {
                return;
            }
            /* FIX: validate input using StringEscapeUtils */
            String uname = StringEscapeUtils.escapeXml(tokens[0]);
            String pword = StringEscapeUtils.escapeXml(tokens[1]);
            /* build xpath */
            XPath xp = XPathFactory.newInstance().newXPath();
            InputSource inxml = new InputSource(xmldoc);
            String query = "//users/user[name/text()='" + uname +
                           "' and pass/text()='" + pword + "']" +
                           "/secret/text()";
            String secret = (String)xp.evaluate(query, inxml, XPathConstants.STRING);
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

