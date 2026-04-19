/*
 * @description Missing Release of File Descriptor or Handle After Effective Lifetime.  Performs some, but not all, necessary resource cleanup (BufferedReader is not closed).
 * 
 * */

package testcases.CWE775_Missing_Release_of_File_Descriptor_or_Handle;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE775_Missing_Release_of_File_Descriptor_or_Handle__FileReader_01
		extends AbstractTestCase 
{	
    public void bad()
	{
		BufferedReader buffread = null;
		FileReader fread = null;
		try
		{
			File f = new File("c:\\file.txt");
			fread = new FileReader(f);
			buffread = new BufferedReader(fread);
	        String readString = buffread.readLine();
	        
	        IO.writeLine(readString);
		}
		catch(IOException e)
		{
            IO.logger.log(Level.WARNING, "Error with stream reading", e);
		}
		finally
		{
			try {
				if( fread != null ) {
					fread.close();
				}
			}
			catch( IOException ioe ) {
				IO.logger.log(Level.WARNING, "Error closing FileReader", ioe);
			}
			
			/* FLAW: BufferedReader not closed */
		}
	}
	
	private void good1()
	{		
		BufferedReader buffread = null;
		FileReader fread = null;
		try
		{
			File f = new File("c:\\file.txt");
			fread = new FileReader(f);
			buffread = new BufferedReader(fread);
	        String readString = buffread.readLine();
	        
	        IO.writeLine(readString);
		}
		catch(IOException e)
		{
            IO.logger.log(Level.WARNING, "Error with stream reading", e);
		}
		finally
		{
			try {
				if( fread != null ) {
					fread.close();
				}
			}
			catch( IOException ioe ) {
				IO.logger.log(Level.WARNING, "Error closing FileReader", ioe);
			}
			
			/* FIX: BufferedReader closed appropriately */
            try
            {
                if (buffread != null)
                {
                    buffread.close();
                }
            }
            catch( IOException e )
            {
                IO.logger.log(Level.WARNING, "Error closing BufferedReader", e);
            }
			
		}
	}
	
	public void good() throws IOException 
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
