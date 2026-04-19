/*
 * @description 
 * Java code makes a call into a potentially unsafe unmanaged DLL.
 * The bad case allows the user to specify the length of the input string.
 * In addition, the case does not recognize the limitations of the unmanaged
 * code and does no input validation.
 * 
 * In order to get this to run, you need to place the JNITest.dll (Windows)
 * or libJNITest (Linux) in your Java library path.
 * 
 * */

package testcases.CWE111_Unsafe_JNI;

import testcasesupport.AbstractTestCaseBadOnly;
import testcasesupport.IO;
import java.io.*;

import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE111_Unsafe_JNI__console_01 extends AbstractTestCaseBadOnly {

	native String test(String s1, int len);
	
	static 
	{
		try
		{
			System.loadLibrary("JNITest"); /* load JNITest.dll or libJNITest.so */
		}
		catch(UnsatisfiedLinkError ule)
		{
			IO.logger.log(Level.WARNING, "Error, the library does not exist", ule);
		}
	}
    
    public void bad() throws IOException {
        InputStreamReader inread = null;
        BufferedReader buffread = null;

		int num = 0;
		try
		{
            IO.writeLine("Enter a string: (asdf)" );

            inread = new InputStreamReader(System.in, "UTF-8");
            buffread = new BufferedReader(inread);
            
            String text = buffread.readLine();
            
            IO.writeLine("How long was your string? (200) ");
			num = Integer.parseInt(buffread.readLine());
		
            IO.writeLine("Result from native method: " + test(text, num)); /* FLAW: Using an unsafe JNI method */
		}
		catch(IOException ioe)
		{
			IO.logger.log(Level.WARNING, "Error with stream reading", ioe);
			return;
		}
        finally {
            try {
                if( buffread != null ) {
                    buffread.close();
                }
            }
            catch( IOException e ) {
				IO.logger.log(Level.WARNING, "Error closing BufferedReader", e);
            }
            finally {
                try {
                    if( inread != null ) {
                        inread.close();
                    }
                }
                catch( IOException e ) {
					IO.logger.log(Level.WARNING, "Error closing InputStreamReader", e);
                }
            }
        }
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
