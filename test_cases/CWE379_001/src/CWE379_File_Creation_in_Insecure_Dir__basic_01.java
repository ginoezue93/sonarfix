/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE379_File_Creation_in_Insecure_Dir__basic_01.java
Label Definition File: CWE379_File_Creation_in_Insecure_Dir__basic.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 379 File Creation in Insecure Directory
* Sinks:
*    GoodSink: Restrict permissions on directory
*    BadSink : Permissions never set on directory
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE379_File_Creation_in_Insecure_Dir;

import testcasesupport.*;

import javax.servlet.http.*;
import java.io.*;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE379_File_Creation_in_Insecure_Dir__basic_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {

        FileOutputStream fos = null;
        OutputStreamWriter oswrite = null;
        BufferedWriter buffwrite = null;
        String dirname = ".\\src\\testcases\\CWE379_File_Creation_in_Insecure_Dir\\insecureDir";

        try {
            File dir = new File(dirname);

            /* FLAW: Permissions never set on directory */

            boolean success = dir.mkdir();
            if( success )
            {
                IO.writeLine("Directory created");
                File temp = File.createTempFile("temp", "1234", dir);
                /* Set file as writable by owner, readable by owner, not executable (if file system supports it) */
                if (!temp.setWritable(true, true))
                {
                    IO.logger.log(Level.WARNING, "Could not set Writable permissions");
                }
                if (!temp.setReadable(true, true))
                {
                    IO.logger.log(Level.WARNING, "Could not set Readable permissions");
                }
                if (!temp.setExecutable(false))
                {
                    IO.logger.log(Level.WARNING, "Could not set Executable permissions");
                }
                /* Write something to the file */
                fos = new FileOutputStream(temp);
                oswrite = new OutputStreamWriter(fos, "UTF-8");
                buffwrite = new BufferedWriter(oswrite);
                buffwrite.write(42);
            }
        }
        catch ( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error writing to temporary file", ioe);
        }
        finally {
            try {
                if (buffwrite != null)
                {
                    buffwrite.close();
                }
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedWriter", ioe);
            }

            try {
                if (oswrite != null)
                {
                    oswrite.close();
                }
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error closing OutputStreamWriter", ioe);
            }

            try {
                if (fos != null)
                {
                    fos.close();
                }
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error closing FileOutputStream", ioe);
            }
        }

    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {

        FileOutputStream fos = null;
        OutputStreamWriter oswrite = null;
        BufferedWriter buffwrite = null;
        String dirname = ".\\src\\testcases\\CWE379_File_Creation_in_Insecure_Dir\\secureDir";

        try {
            File dir = new File(dirname);

            /* FIX: Set dir as writable by owner, readable by owner, not executable (if file system supports it) */
            if (!dir.setWritable(true, true))
            {
                IO.logger.log(Level.WARNING, "Could not set Writable permissions");
            }
            if (!dir.setReadable(true, true))
            {
                IO.logger.log(Level.WARNING, "Could not set Readable permissions");
            }
            if (!dir.setExecutable(false))
            {
                IO.logger.log(Level.WARNING, "Could not set Executable permissions");
            }

            boolean success = dir.mkdir();
            if( success )
            {
                IO.writeLine("Directory created");
                File temp = File.createTempFile("temp", "1234", dir);
                /* Set file as writable by owner, readable by owner, not executable (if file system supports it) */
                if (!temp.setWritable(true, true))
                {
                    IO.logger.log(Level.WARNING, "Could not set Writable permissions");
                }
                if (!temp.setReadable(true, true))
                {
                    IO.logger.log(Level.WARNING, "Could not set Readable permissions");
                }
                if (!temp.setExecutable(false))
                {
                    IO.logger.log(Level.WARNING, "Could not set Executable permissions");
                }
                /* Write something to the file */
                fos = new FileOutputStream(temp);
                oswrite = new OutputStreamWriter(fos, "UTF-8");
                buffwrite = new BufferedWriter(oswrite);
                buffwrite.write(42);
            }
        }
        catch ( IOException ioe )
        {
            IO.logger.log(Level.WARNING, "Error writing to temporary file", ioe);
        }
        finally {
            try {
                if (buffwrite != null)
                {
                    buffwrite.close();
                }
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedWriter", ioe);
            }

            try {
                if (oswrite != null)
                {
                    oswrite.close();
                }
            }
            catch (IOException ioe)
            {
                IO.logger.log(Level.WARNING, "Error closing OutputStreamWriter", ioe);
            }

            try {
                if (fos != null)
                {
                    fos.close();
                }
            }
            catch (IOException ioe)
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

