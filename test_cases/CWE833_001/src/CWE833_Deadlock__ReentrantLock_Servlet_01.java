/*
 * @description Demonstrates a deadlock caused by obtaining locks in a different order in different functions in a Servlet that accesses shared variables.  Servlets are inherently multithreaded, so we don't need to actually start threads in the bad() and goodX() functions.
 * 
 * */
package testcases.CWE833_Deadlock;

import java.util.concurrent.locks.ReentrantLock;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.logging.Level;
import java.util.logging.Logger;

import testcasesupport.IO;
import testcasesupport.AbstractTestCaseServlet;

public class CWE833_Deadlock__ReentrantLock_Servlet_01 extends AbstractTestCaseServlet {
	private static final long serialVersionUID = 1L;

  /* bad(): Obtain locks in different order in bad_add and bad_mult, causing a deadlock */
  static private int bada = 3;
  static private final ReentrantLock bada_relock = new ReentrantLock();

  static private int badb = 5;
  static private final ReentrantLock badb_relock = new ReentrantLock();
  
  static public void bad_add()
  {
    bada_relock.lock();
    
    /* Would like to wait a bit here to allow for a context switch or for another thread to "catch up", but we can't call Thread.sleep() since that is not allowed in a Servlet (CWE-383: J2EE Bad Practices: Direct Use of Threads) */  

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
    
    /* Would like to wait a bit here to allow for a context switch or for another thread to "catch up", but we can't call Thread.sleep() since that is not allowed in a Servlet (CWE-383: J2EE Bad Practices: Direct Use of Threads) */  

    bada_relock.lock();
    try {
      bada = bada * badb;
    } finally {
      bada_relock.unlock();
      badb_relock.unlock();
    }
  }  
	
	public void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable 
	{
    /* Branch so that not all requests call the same method.  If a valid request and an invalid
       one come in at the same time, a deadlock will result */
    if(request.isRequestedSessionIdValid()) {
      bad_add();
    } else {
      bad_mult();
    }
    
    /* write output */
    response.getWriter().write(bada);
	}

 
  /* good1() - obtain locks in same order in good1_add() and good1_mult() */
  static private int good1a = 3;
  static private final ReentrantLock good1a_relock = new ReentrantLock();

  static private int good1b = 5;
  static private final ReentrantLock good1b_relock = new ReentrantLock();
  
  static public void good1_add()
  {
    good1a_relock.lock();
    
    /* Would like to wait a bit here to allow for a context switch or for another thread to "catch up", but we can't call Thread.sleep() since that is not allowed in a Servlet (CWE-383: J2EE Bad Practices: Direct Use of Threads) */  

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
    
    /* Would like to wait a bit here to allow for a context switch or for another thread to "catch up", but we can't call Thread.sleep() since that is not allowed in a Servlet (CWE-383: J2EE Bad Practices: Direct Use of Threads) */  

    good1b_relock.lock();
    try {
      good1a = good1a * good1b;
    } finally {
      good1b_relock.unlock();
      good1a_relock.unlock();
    }
  }  
	
	public void good1(HttpServletRequest request, HttpServletResponse response) throws Throwable 
	{
    /* Branch so that not all requests call the same method. */
    if(request.isRequestedSessionIdValid()) {
      good1_add();
    } else {
      good1_mult();
    }
    
    /* write output */
    response.getWriter().write(good1a);
	}  
  
  public void good(HttpServletRequest request, HttpServletResponse response) throws Throwable 
  {
    good1(request, response);
  } 
}
