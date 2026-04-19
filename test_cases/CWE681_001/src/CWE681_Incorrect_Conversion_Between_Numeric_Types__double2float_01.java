/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE681_Incorrect_Conversion_Between_Numeric_Types__double2float_01.java
Label Definition File: CWE681_Incorrect_Conversion_Between_Numeric_Types.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 681 Incorrect Conversion Between Numeric Types
* Sinks: double2float
*    GoodSink: check for conversion error
*    BadSink : explicit cast
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE681_Incorrect_Conversion_Between_Numeric_Types;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.*;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE681_Incorrect_Conversion_Between_Numeric_Types__double2float_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {

        BufferedReader bufread2 = null;
        InputStreamReader inread2 = null;
        boolean errored = false;
        try
        {
            /* Enter: 1e-50, result should be 0.0 (for bad case)
             *
             * Note: alternate input
             * 999999999999999999999999999999999999999999999999999999999999999
             */
            inread2 = new InputStreamReader(System.in, "UTF-8");
            bufread2 = new BufferedReader(inread2);
            System.out.print("Enter double number (1e-50): ");
            double num = 0;
            try
            {
                num = Double.parseDouble(bufread2.readLine());
            }
            catch(Exception e)
            {
                IO.writeLine("Error parsing number");
                errored = true;
            }

            /* FLAW: should not cast without checking if conversion is safe */
            IO.writeLine("" + (float)num);
        }
        catch( Exception e )
        {
            IO.logger.log(Level.WARNING, "Error!", e);
        }
        finally
        {
            try
            {
                if( bufread2 != null )
                {
                    bufread2.close();
                }
            }
            catch( IOException e )
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedReader", e);
            }

            try
            {
                if( inread2 != null )
                {
                    inread2.close();
                }
            }
            catch( IOException e )
            {
                IO.logger.log(Level.WARNING, "Error closing InputStreamReader", e);
            }

            if( errored )
            {
                IO.logger.log(Level.WARNING, "Error parsing number");
            }
        }

    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {

        BufferedReader bufread2 = null;
        InputStreamReader inread2 = null;
        boolean errored = false;

        try
        {
            inread2 = new InputStreamReader(System.in, "UTF-8");
            bufread2 = new BufferedReader(inread2);
            System.out.print("Enter double number (1e-50): ");
            double num = 0;
            try
            {
                num = Double.parseDouble(bufread2.readLine());
            }
            catch(Exception e)
            {
                IO.writeLine("Error parsing number");
                errored = true;
            }

            /* FIX: check for conversion error */
            if (num > Float.MAX_VALUE ||
                    num < Float.MIN_VALUE)
            {
                IO.writeLine("Error, cannot safely cast this number to a float!");
                return;
            }

            IO.writeLine("" + (float)num);
        }
        catch( Exception e )
        {
            IO.logger.log(Level.WARNING, "Error!", e);
        }
        finally
        {
            try
            {
                if( bufread2 != null )
                {
                    bufread2.close();
                }
            }
            catch( IOException e )
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedReader", e);
            }

            try
            {
                if( inread2 != null )
                {
                    inread2.close();
                }
            }
            catch( IOException e )
            {
                IO.logger.log(Level.WARNING, "Error closing InputStreamReader", e);
            }

            if( errored )
            {
                IO.logger.log(Level.WARNING, "Error parsing number");
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

