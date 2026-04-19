/*
 * @description Demonstrates a deadlock caused by synchronized methods in objects that call one another in multithreaded code.  Implementation based on http://download.oracle.com/javase/tutorial/essential/concurrency/deadlock.html.
 * 
 * */
package testcases.CWE833_Deadlock;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.AbstractTestCase;
import testcasesupport.IO;

public class CWE833_Deadlock__synchronized_methods_Thread_01 extends AbstractTestCase 
{

  /* Bad - Call to a synchronized method on another object while holding lock on this object */
	public synchronized void bad_bow(CWE833_Deadlock__synchronized_methods_Thread_01 bower) {
		IO.writeLine("bad_bow");
    try { 
      Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
    } catch (InterruptedException e) {
      IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
    }
		bower.bad_bowBack(this); /* FLAW: Call to a synchronized method on another object while holding lock on this object */
	}
	public synchronized void bad_bowBack(CWE833_Deadlock__synchronized_methods_Thread_01 bower) {
		IO.writeLine("bad_bowBack");
	}
	
	public void bad() throws InterruptedException {
    /* Create objects */
    final CWE833_Deadlock__synchronized_methods_Thread_01 a = new CWE833_Deadlock__synchronized_methods_Thread_01();
    final CWE833_Deadlock__synchronized_methods_Thread_01 b = new CWE833_Deadlock__synchronized_methods_Thread_01();

    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { a.bad_bow(b); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { b.bad_bow(a); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
      
    /* Wait for threads to finish (though they never will since they are deadlocked) */
    ta.join();
    tb.join();
  }


  /* Good1 - Call to synchronized method on another object is made after giving up "lock" on this object */
	public void good1_bow(CWE833_Deadlock__synchronized_methods_Thread_01 bower) {
  	synchronized(this) {
      IO.writeLine("good1_bow");
      try { 
        Thread.sleep(1000); /* sleep for a bit to allow a context switch or the other thread to "catch up" */
      } catch (InterruptedException e) {
        IO.logger.log(Level.WARNING, "Sleep Interrupted", e);
      }
    }
		bower.good1_bowBack(this); /* FIX: Call to synchronized method on another object is made after giving up "lock" on this object */
	}

	public synchronized void good1_bowBack(CWE833_Deadlock__synchronized_methods_Thread_01 bower) {
		IO.writeLine("good1_bowBack");
	}
	
	private void good1()  throws InterruptedException {
    /* Create objects */
    final CWE833_Deadlock__synchronized_methods_Thread_01 a = new CWE833_Deadlock__synchronized_methods_Thread_01();
    final CWE833_Deadlock__synchronized_methods_Thread_01 b = new CWE833_Deadlock__synchronized_methods_Thread_01();

    /* Create threads */
    Thread ta = new Thread(new Runnable() {
        public void run() { a.good1_bow(b); }
    });
    Thread tb = new Thread(new Runnable() {
        public void run() { b.good1_bow(a); }
    });
    
    /* Start threads */
    ta.start();
    tb.start();
    
    /* Wait for threads to finish */
    ta.join();
    tb.join();
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
