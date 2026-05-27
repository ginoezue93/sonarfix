/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE523_Unprotected_Cred_Transport__Servlet_01.java
Label Definition File: CWE523_Unprotected_Cred_Transport__Servlet.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 523 Unprotected Transport of Credentials
* Sinks: non_ssl
*    GoodSink: Send across SSL connection
*    BadSink : Send across non-SSL connection
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE523_Unprotected_Cred_Transport;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.*;

public class CWE523_Unprotected_Cred_Transport__Servlet_01 extends AbstractTestCaseServlet
{

    public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        PrintWriter out = null;
        try
        {
            out = response.getWriter();

            /* FLAW: transmitting login credentials across a non-SSL connection */
            out.println("<form action='http://hostname.com/j_security_check' method='post'>");
            out.println("<table>");
            out.println("<tr><td>Name:</td>");
            out.println("<td><input type='text' name='j_username'></td></tr>");
            out.println("<tr><td>Password:</td>");
            out.println("<td><input type='password' name='j_password' size='8'></td>");
            out.println("</tr>");
            out.println("</table><br />");
            out.println("<input type='submit' value='login'>");
            out.println("</form>");
        }
        catch( IOException e )
        {
            IO.writeLine("There was a problem writing");
        }
        finally
        {
            if( out != null )
            {
                out.close();
            }
        }

    }

    public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        good1(request, response);
    }

    private void good1(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        PrintWriter out = null;
        try
        {
            out = response.getWriter();

            /* FIX: ensure the connection is secure (https) */
            out.println("<form action='https://hostname.com/j_security_check' method='post'>");
            out.println("<table>");
            out.println("<tr><td>Name:</td>");
            out.println("<td><input type='text' name='j_username'></td></tr>");
            out.println("<tr><td>Password:</td>");
            out.println("<td><input type='password' name='j_password' size='8'></td>");
            out.println("</tr>");
            out.println("</table><br />");
            out.println("<input type='submit' value='login'>");
            out.println("</form>");
        }
        catch( IOException e )
        {
            IO.writeLine("There was a problem writing");
        }
        finally
        {
            if( out != null )
            {
                out.close();
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

