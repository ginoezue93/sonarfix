/*
 * @description Demonstrates use of lock() more times than unlock() in multithreaded code that accesses a shared variable.
 * 
 * */
package testcases.CWE764_Multiple_Locks;

import java.util.concurrent.locks.ReentrantLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE764_Multiple_Locks__ReentrantLock_Thread_01 extends AbstractTestCase 
{
  /* bad(): Use lock() twice and unlock() once */
  static private int badint = 1;
  static private final ReentrantLock badrelock = new ReentrantLock();

  static public void bad_double() 
  {
    badrelock.lock(); 
    badrelock.lock(); /* FLAW: Code uses lock() twice (and unlock() once), so the second thread will never be able to get lock */

    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      badint = badint * 2;
    } finally {
      badrelock.unlock(); /* Only one unlock(), so the lock will still be held when the thread ends, meaning no other threads can get the lock */
    }
  }
	
	public void bad() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE764_Multiple_Locks__ReentrantLock_Thread_01.bad_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE764_Multiple_Locks__ReentrantLock_Thread_01.bad_double(); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish (though they never will because the second thread will never be able to get the lock that the first thread incorrectly locked twice) */
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
    good1relock.lock(); /* FIX: Only use lock() once */
    /* good practice is to unlock() in a finally block, see http://download.oracle.com/javase/6/docs/api/java/util/concurrent/locks/ReentrantLock.html */
    try{ 
      good1int = good1int * 2;
    } finally {
      good1relock.unlock();
    }
  }
  
  private void good1() throws InterruptedException
  {        
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE764_Multiple_Locks__ReentrantLock_Thread_01.good1_double(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE764_Multiple_Locks__ReentrantLock_Thread_01.good1_double(); }
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
