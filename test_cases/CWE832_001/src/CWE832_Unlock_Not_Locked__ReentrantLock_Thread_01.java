/*
 * @description Demonstrates use of unlock() on a lock that is not locked in multithreaded code that accesses a shared variable.
 * 
 * */
package testcases.CWE832_Unlock_Not_Locked;

import java.util.concurrent.locks.ReentrantLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE832_Unlock_Not_Locked__ReentrantLock_Thread_01 extends AbstractTestCase 
{
  /* bad(): Use unlock() on resource that is not locked */
  static private int badint = 1;
  static private final ReentrantLock badrelock = new ReentrantLock();

  static public void bad_double() 
  {
    /* Missing lock here */
    
    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      badint = badint * 2;
    } finally {
      badrelock.unlock(); /* FLAW: Calls unlock() on a lock which is not locked, which will throw an IllegalMonitorStateException */
    }
  }
	
	public void bad() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE832_Unlock_Not_Locked__ReentrantLock_Thread_01.bad_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE832_Unlock_Not_Locked__ReentrantLock_Thread_01.bad_double(); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish */
    ta.join();
    tb.join();

    /* Write output */
    IO.writeLine(badint);  
	}

  
  /* good1(): Use a ReentrantLock properly (use lock() once and unlock() once) */
  static private int good1int = 1;
  static private final ReentrantLock good1relock = new ReentrantLock();

  static public void good1_double() 
  {
    good1relock.lock();  /* Inserted lock here that was missing in bad() */
    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      good1int = good1int * 2;
    } finally {
      good1relock.unlock(); /* FIX: Only unlock() a lock that has been locked. */
    }
  }
  
  private void good1() throws InterruptedException
  {        
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE832_Unlock_Not_Locked__ReentrantLock_Thread_01.good1_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE832_Unlock_Not_Locked__ReentrantLock_Thread_01.good1_double(); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish */
    ta.join();
    tb.join();

    /* Write output */
    IO.writeLine(good1int);
  }  
  
  
  public void good() throws InterruptedException 
  {
    good1();
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
