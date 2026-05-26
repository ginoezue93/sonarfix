/*
 * @description Demonstrates a deadlock caused by obtaining locks in a different order in different functions in multithreaded code that accesses shared variables.
 * 
 * */
package testcases.CWE833_Deadlock;

import java.util.concurrent.locks.ReentrantLock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE833_Deadlock__ReentrantLock_Thread_01 extends AbstractTestCase 
{
  /* bad(): Obtain locks in different order in bad_add and bad_mult, causing a deadlock */
  static private int bada = 3;
  static private final ReentrantLock bada_relock = new ReentrantLock();

  static private int badb = 5;
  static private final ReentrantLock badb_relock = new ReentrantLock();
  
  static public void bad_add()
  {
    bada_relock.lock();
    try { 
      Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
    } catch (InterruptedException e) {
      IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
    }
    badb_relock.lock();
    try {
      bada = bada + badb;
    } finally {
      badb_relock.unlock();
      bada_relock.unlock();
    }
  }
  
  static public void bad_mult()
  {
    badb_relock.lock(); /* FLAW: obtain locks in the opposite order as in bad_add() */
    try { 
      Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
    } catch (InterruptedException e) {
      IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
    }
    bada_relock.lock();
    try {
      bada = bada * badb;
    } finally {
      bada_relock.unlock();
      badb_relock.unlock();
    }
  }
	
	public void bad() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__ReentrantLock_Thread_01.bad_add(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__ReentrantLock_Thread_01.bad_mult(); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish (though they never will since they are deadlocked) */
    ta.join();
    tb.join();

    /* write output */
    IO.writeLine(bada);
  
	}


  /* good1() - obtain locks in same order in good1_add() and good1_mult() */
  static private int good1a = 3;
  static private final ReentrantLock good1a_relock = new ReentrantLock();

  static private int good1b = 5;
  static private final ReentrantLock good1b_relock = new ReentrantLock();
  
  static public void good1_add()
  {
    good1a_relock.lock();
    try { 
      Thread.sleep(1000); /* sleep for a bit to allow a context switch */
    } catch (InterruptedException e) {
      IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
    }
    good1b_relock.lock();
    try {
      good1a = good1a + good1b;
    } finally {
      good1b_relock.unlock();
      good1a_relock.unlock();
    }
  }
  
  static public void good1_mult()
  {
    good1a_relock.lock(); /* FIX: obtain locks in the same order as in good1_add() */
    try { 
      Thread.sleep(1000); /* sleep for a bit to allow a context switch */
    } catch (InterruptedException e) {
      IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
    }
    good1b_relock.lock();
    try {
      good1a = good1a * good1b;
    } finally {
      good1b_relock.unlock();
      good1a_relock.unlock();
    }
  }
	
	public void good1() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__ReentrantLock_Thread_01.good1_add(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__ReentrantLock_Thread_01.good1_mult(); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish */
    ta.join();
    tb.join();

    /* write output */
    IO.writeLine(good1a);

	}
  
  public void good() throws Throwable 
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
