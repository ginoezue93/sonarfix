/*
 * @description Demonstrates use of unlock() more times than lock() in multithreaded code that accesses a shared variable.
 * 
 * */
package testcases.CWE765_Multiple_Unlocks;

import java.util.concurrent.locks.ReentrantLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE765_Multiple_Unlocks__ReentrantLock_Thread_01 extends AbstractTestCase 
{
  /* bad(): Use lock() once and unlock() twice */
  static private int badint = 1;
  static private final ReentrantLock badrelock = new ReentrantLock();

  static public void bad_double() 
  {
    badrelock.lock(); 

    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      badint = badint * 2;
    } finally {
      badrelock.unlock();    
      badrelock.unlock(); /* FLAW: Code uses unlock() twice (and lock() once), which will throw an IllegalMonitorStateException */
    }
  }
	
	public void bad() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE765_Multiple_Unlocks__ReentrantLock_Thread_01.bad_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE765_Multiple_Unlocks__ReentrantLock_Thread_01.bad_double(); }
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
    good1relock.lock(); 
    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      good1int = good1int * 2;
    } finally {
      good1relock.unlock(); /* FIX: Only use unlock() once */
    }
  }
  
  private void good1() throws InterruptedException
  {        
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE765_Multiple_Unlocks__ReentrantLock_Thread_01.good1_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE765_Multiple_Unlocks__ReentrantLock_Thread_01.good1_double(); }
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
