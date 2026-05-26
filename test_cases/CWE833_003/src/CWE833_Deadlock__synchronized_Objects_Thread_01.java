/*
 * @description Demonstrates a deadlock caused by synchronizing on objects in a different order in different functions in multithreaded code that accesses shared variables.
 * 
 * */
package testcases.CWE833_Deadlock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE833_Deadlock__synchronized_Objects_Thread_01 extends AbstractTestCase 
{
  /* bad(): Synchronize on objects in different order in bad_add and bad_mult, causing a deadlock */
  static private int bada = 3;
  static private final Object bada_lock = new Object();

  static private int badb = 5;
  static private final Object badb_lock = new Object();
  
  static public void bad_add()
  {
    synchronized(bada_lock) {
      try { 
        Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
      } catch (InterruptedException e) {
        IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
      }
      synchronized(badb_lock) {
        bada = bada + badb;
      }
    }
  }
  
  static public void bad_mult()
  {
    synchronized(badb_lock) { /* FLAW: Synchronize on objects in the opposite order as in bad_add() */
      try { 
        Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
      } catch (InterruptedException e) {
        IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
      }
      synchronized(bada_lock) {
        bada = bada * badb;
      }
    }
  }
	
	public void bad() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__synchronized_Objects_Thread_01.bad_add(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__synchronized_Objects_Thread_01.bad_mult(); }
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


  /* good1() - Synchronize on objects in same order in good1_add() and good1_mult() */
  static private int good1a = 3;
  static private final Object good1a_lock = new Object();

  static private int good1b = 5;
  static private final Object good1b_lock = new Object();
  
  static public void good1_add()
  {
    synchronized(good1a_lock) {
      try { 
        Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
      } catch (InterruptedException e) {
        IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
      }
      synchronized(good1b_lock) {
        good1a = good1a + good1b;
      }
    }
  }
  
  static public void good1_mult()
  {
    synchronized(good1a_lock) { /* FIX: Synchronize on objects in the same order as in good1_add() */
      try { 
        Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
      } catch (InterruptedException e) {
        IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
      }
      synchronized(good1b_lock) {
        good1a = good1a * good1b;
      }
    }
  }
	
	public void good1() throws Throwable 
	{
    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__synchronized_Objects_Thread_01.good1_add(); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { CWE833_Deadlock__synchronized_Objects_Thread_01.good1_mult(); }
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
