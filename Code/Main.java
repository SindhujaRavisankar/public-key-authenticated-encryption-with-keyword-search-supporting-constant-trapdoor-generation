import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.*;
import javax.swing.*;
import java.awt.*;
import java.awt.Color;
import javax.swing.border.EmptyBorder;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
public class Main extends JFrame{
    private JTextArea  m1, m2, m31, m32, m33 ;
    private JLabel m, p31, p32;
    private JButton b1, b2;
public Main(){
    // main code start from here
    Pairing pairing = PairingFactory.getPairing("params.properties");
    PairingFactory.getInstance().setUsePBCWhenPossible(true);

    // initiate p
    Element P = pairing.getG1().newRandomElement().getImmutable();
    System.out.println("P is :" + P);

    // initiate g
    Element g = pairing.getG1().newRandomElement().getImmutable();
    System.out.println("g is :"+g);

    Element x1 = pairing.getZr().newRandomElement().getImmutable();
    Element x2 = pairing.getZr().newRandomElement().getImmutable();
    Element x3 = pairing.getZr().newRandomElement().getImmutable();
    Element x4 = pairing.getZr().newRandomElement().getImmutable();
            /*
            // public key generation
               Element pr- public key of Receiver and ps- public key of sender */

    Element pr1=g.powZn(x1);
    System.out.println("public key1: "+pr1);
    Element pr2=g.powZn(x2);
    System.out.println("public key2: "+pr2);
    Element pr3=g.powZn(x3);
    System.out.println("public key3: "+pr3);

    // Skr1= x1,skr2=x2,skr3=x3 and skr4=x4 are the serect keys
    Element skr1=x1;
    Element skr2=x2;
    Element skr3=x3;
    Element skr4=x4;

    // Key Generation for receiver  - ends here.

    // Key Generation for Sender  - Starts here.
    // y is the Secret key of sender.
    Element y = pairing.getZr().newRandomElement().getImmutable();

    // public key of Sender is pks
    Element pks=g.powZn(y);
    System.out.println("public key Sender: "+pks);

    // Key Generation for Sender  - Ends here.

    // Keyword Encryption Starts here
    /* Random number for powers */
    Element r1 = pairing.getZr().newRandomElement().getImmutable();
    Element r2 = pairing.getZr().newRandomElement().getImmutable();

    /* Encryption*/
    Element h1_hash_int = pairing.getZr().newRandomElement().getImmutable();
    Element c1 = (pr2.powZn(h1_hash_int).add(pr3)).powZn(r1);

    Element c2 = g.powZn(r1);

    Element h2_hash_int = pairing.getZr().newRandomElement().getImmutable();
    Element h3_hash_int = pairing.getZr().newRandomElement().getImmutable();
    Element c3 = ((pr2.powZn(h2_hash_int).add(pr3)).powZn(r2)).add(g.powZn(h3_hash_int.mul(r1)));

    Element c4_hash_point = pairing.getG1().newRandomElement().getImmutable();
    Element c4 = c4_hash_point.powZn(r2);

    Element c5_hash_point = pairing.getG1().newRandomElement().getImmutable();
    Element c5 = c5_hash_point.powZn(r1);

    System.out.println("c1 is : " + c1);
    System.out.println("c2 is : " + c2);
    System.out.println("c3 is : " + c3);
    System.out.println("c4 is : " + c4);
    System.out.println("c5 is : " + c5);

    // Keyword Encryption - ends here

    //Trapdoor Generation Starts here

    Element r3 = pairing.getZr().newRandomElement().getImmutable();
    //Element h1_trapdoor_hash_int = pairing.getZr().newRandomElement().getImmutable();
    // Element tw1pow = r3.div((skr2.mul(h1_trapdoor_hash_int).add(x3)));
    Element tw1pow = r3.mul((skr2.mul(h1_hash_int).add(x3)).invert());
    Element Tw1 = g.powZn(tw1pow);
    System.out.println("Tw1 is :" + Tw1);
    Element Tw2 = g.powZn(r3);
    System.out.println("Tw2 is :" + Tw2);

    // Trapdoor generation ends here
    // Test
    Element e1= pairing.pairing(c1,Tw1);
    Element e2= pairing.pairing(c2,Tw2);
    System.out.println("e1 is : " +e1);
    System.out.println("e2 is : " +e2);
    if(e1.isEqual(e2))
    {
        System.out.println("matched");
    }
    else {
        System.out.println("not match");
    }
    // update key generation starts here
    Element upd_h3_hash_point= pairing.getZr().newRandomElement().getImmutable();
    Element upd_h2_hash_point= pairing.getZr().newRandomElement().getImmutable();
    Element uks1=upd_h3_hash_point;
    System.out.println("Updated Key generation1 is : "+uks1);
    //Element uks2_div= (x2.mul(upd_h2_hash_point).add(x3).invert());
    Element uks2=x4.mul((x2.mul(upd_h2_hash_point).add(x3).invert()));
    System.out.println("Updated Key generation2 is : "+uks2);

    // update key generation ends here

    // UC is Update Encryption starts here
    Element H = pairing.getG1().newRandomElement().getImmutable();
    Element UC1 = pairing.pairing(H,c2);
    System.out.println("update enc1 :" +UC1);
    Element UC2 = pairing.pairing(c5,g);
    System.out.println("update enc2 :" +UC2);
        Element c6 = g.powZn(r2.mul(x4));
        System.out.println("c6 is " + c6);
        Element C = pairing.getG1().newRandomElement().getImmutable();
        Element UC = pairing.pairing(C,c6);
        System.out.println("Updated Encryption is : " + UC);

        // UC is Update Encryption ends here

        //Constant Trapdoor generation starts here
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element utw1 = g.powZn(x4.mul(r));
        System.out.println("Updated Trapdoor1 :" + utw1);
        Element utw2 = c4_hash_point.powZn(r);
        System.out.println("Updated Trapdoor2 :" + utw2);

        //Constant Trapdoor generation ends here

        //updated test starts here
        Element UE1=pairing.pairing(c4,utw1);
        System.out.println("UE1 is : "+UE1);
        Element UE2=pairing.pairing(c6,utw2);
        System.out.println("UE2 is : "+UE2);
        if(UE1.isEqual(UE2)){
            System.out.println("Updated test matched : \n "+UE1);
        }
        else {
            System.out.println("Updated test not matched");
        }

    // main code ends here

    setTitle("Welcome");
    setSize(getMaximumSize());
    setLocationRelativeTo(null);

    JLabel w1 = new JLabel("Public Key Authenticated Encryption with keyword search supporting Constant Trapdoor Generation");
    w1.setFont(new Font("Times New Roman",Font.BOLD,26));
    w1.setPreferredSize(new Dimension(1200,100));

    JLabel m=new JLabel("Message ");
    m.setPreferredSize(new Dimension(100, 50));
    m.setFont(new Font("Times New Roman",Font.BOLD,18));

    JTextArea m1=new JTextArea();
    m1.setPreferredSize(new Dimension(550, 100));
    m1.setBorder(BorderFactory.createLineBorder(Color.BLACK,1));

    JTextArea m2 = new JTextArea();
    m2.setPreferredSize(new Dimension(550, 100));
    m2.setBorder(BorderFactory.createLineBorder(Color.BLACK,1));

    JLabel k1=new JLabel("Public Key ");
    k1.setPreferredSize(new Dimension(100, 50));
    k1.setFont(new Font("Times New Roman",Font.BOLD,18));


    JTextArea m31 = new JTextArea();
    m31.setPreferredSize(new Dimension(550, 100));

    JTextArea m32 = new JTextArea();
    m32.setPreferredSize(new Dimension(550, 100));

    JLabel k2=new JLabel("     ");
    k2.setPreferredSize(new Dimension(350, 50));

    JLabel k3=new JLabel("     ");
    k3.setPreferredSize(new Dimension(450, 50));

    JTextArea m33 = new JTextArea();
    m33.setPreferredSize(new Dimension(550, 100));

    JTextArea m34 = new JTextArea();
    m34.setPreferredSize(new Dimension(550,100));

    JLabel p31 = new JLabel();
    p31.setPreferredSize(new Dimension(300,100));

    JLabel p32 = new JLabel("Sender Public key ");
    p32.setPreferredSize(new Dimension(200, 100));
    p32.setFont(new Font("Times New Roman",Font.BOLD,18));

    JButton b1 = new JButton("Message ");
    b1.setPreferredSize(new Dimension(150,40));
    b1.setFont(new Font("Times New Roman",Font.BOLD,20));
    b1.setForeground(new Color(255, 255, 51).brighter());
    b1.setBackground(new Color(225,0,128).brighter());

    JButton b2 = new JButton("Key Generation ");
    b2.setPreferredSize(new Dimension(200,40));
    b2.setFont(new Font("Times New Roman",Font.BOLD,20));
    b2.setForeground(new Color(255, 255, 51).brighter());
    b2.setBackground(new Color(225,0,128).brighter());

    JButton b3 = new JButton("Encryption");
    b3.setPreferredSize(new Dimension(150,40));
    b3.setFont(new Font("Times New Roman",Font.BOLD,20));
    b3.setForeground(new Color(255, 255, 51).brighter());
    b3.setBackground(new Color(225,0,128).brighter());

    JPanel panel=new JPanel();
    panel.setBackground(new Color(173, 216, 230));

    panel.add(w1);
    panel.add(m);
    panel.add(m1);
    panel.add(m2);
    panel.add(k1);
    panel.add(m31);
    panel.add(m32);
    panel.add(k2);
    panel.add(m33);
    panel.add(p31);
    panel.add(p32);
    panel.add(m34);
    panel.add(k3);
    panel.add(b1);
    panel.add(b2);
    panel.add(b3);

    //action
    b1.addActionListener(new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {

            m1.setText("P (x,y) is :"+P.toString());
            m1.setLineWrap(true);

            // initiate g
            System.out.println("g is :"+g);
            m2.setText("g is :"+g.toString());
            m2.setLineWrap(true);
    }
    });

    b2.addActionListener(new ActionListener() {
                             @Override
                             public void actionPerformed(ActionEvent e) {
                                 // Key Generation for receiver  - Starts here
                                 m31.setText("Public key1 is :"+pr1.toString());
                                 m31.setLineWrap(true);
                                 m32.setText("Public key2 is :"+pr2.toString());
                                 m32.setLineWrap(true);
                                 m33.setText("Public key3 is :"+pr3.toString());
                                 m33.setLineWrap(true);
                                 m34.setText("sender Public key is :"+pks.toString());
                                 m34.setLineWrap(true);
                                 // Key Generation for Sender  - Ends here.
                             }
                         });
    b3.addActionListener(new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {
            JFrame frame1 = new JFrame();
            frame1.setSize(getMaximumSize());
            JPanel panel1 = new JPanel();
            panel1.setBackground(new Color(216, 191, 216));

            JLabel l1 = new JLabel("Cipher text 1: ");
            l1.setPreferredSize(new Dimension(1000,30));
            l1.setFont(new Font("Times New Roman",Font.BOLD,18));
            JLabel l2 = new JLabel("Cipher text 2: ");
            l2.setPreferredSize(new Dimension(1000,30));
            l2.setFont(new Font("Times New Roman",Font.BOLD,18));
            JLabel l3 = new JLabel("Cipher text 3: ");
            l3.setPreferredSize(new Dimension(1000,30));
            l3.setFont(new Font("Times New Roman",Font.BOLD,18));
            JLabel l4 = new JLabel("Cipher text 4: ");
            l4.setPreferredSize(new Dimension(1000,30));
            l4.setFont(new Font("Times New Roman",Font.BOLD,18));
            JLabel l5 = new JLabel("Cipher text 5: ");
            l5.setPreferredSize(new Dimension(1000,30));
            l5.setFont(new Font("Times New Roman",Font.BOLD,18));

            JTextArea lc1 = new JTextArea();
            lc1.setPreferredSize(new Dimension(1000,60));
            lc1.setLineWrap(true);
            JTextArea lc2 = new JTextArea();
            lc2.setPreferredSize(new Dimension(1000,60));
            lc2.setLineWrap(true);
            JTextArea lc3 = new JTextArea();
            lc3.setPreferredSize(new Dimension(1000,60));
            lc3.setLineWrap(true);
            JTextArea lc4 = new JTextArea();
            lc4.setPreferredSize(new Dimension(1000,60));
            lc4.setLineWrap(true);
            JTextArea lc5 = new JTextArea();
            lc5.setPreferredSize(new Dimension(1000,60));
            lc5.setLineWrap(true);

            JButton enc = new JButton("Encryption");
            enc.setPreferredSize(new Dimension(300,30));
            enc.setFont(new Font("Times New Roman",Font.BOLD,20));
            enc.setForeground(new Color(255, 255, 51).brighter());
            enc.setBackground(new Color(225,0,128).brighter());

            JButton t = new JButton("Trapdoor");
            t.setPreferredSize(new Dimension(300,30));

            enc.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    lc1.setText(" Chiper Text1 is "+c1.toString());
                    lc2.setText(" Chiper Text2 is "+c2.toString());
                    lc3.setText(" Chiper Text3 is "+c3.toString());
                    lc4.setText(" Chiper Text4 is "+c4.toString());
                    lc5.setText(" Chiper Text5 is "+c5.toString());
                }
            });
            t.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JFrame frame2 = new JFrame();
                    frame2.setSize(getMaximumSize());
                    JPanel panel3 = new JPanel();
                    panel3.setBackground(Color.pink);

                    JLabel send = new JLabel("Sender");
                    send.setPreferredSize(new Dimension(600, 60));
                    send.setFont(new Font("Times New Roman",Font.BOLD,26));

                    JLabel receiver = new JLabel("Receiver");
                    receiver.setPreferredSize(new Dimension(600, 60));
                    receiver.setFont(new Font("Times New Roman",Font.BOLD,26));


                    JTextArea t1 = new JTextArea();
                    t1.setPreferredSize(new Dimension(600, 80));
                    t1.setLineWrap(true);

                    JTextArea t2 = new JTextArea();
                    t2.setPreferredSize(new Dimension(600, 80));
                    t2.setLineWrap(true);

                    JTextArea t3 = new JTextArea();
                    t3.setPreferredSize(new Dimension(600, 80));
                    t3.setLineWrap(true);

                    JButton tr = new JButton("Trapdoor");
                    tr.setPreferredSize(new Dimension(300, 45));
                    tr.setFont( new Font("Times New Roman",Font.BOLD,20));
                    tr.setForeground(new Color(255,255,255).brighter());
                    tr.setBackground(new Color(3, 59, 90).brighter());

                    JButton test = new JButton("Test ");
                    test.setPreferredSize(new Dimension(300, 45));
                    test.setFont( new Font("Times New Roman",Font.BOLD,20));
                    test.setForeground(new Color(255,255,255).brighter());
                    test.setBackground(new Color(3, 59, 90).brighter());
                    // first test over

                    JButton ut = new JButton("Updated Trapdoor");
                    ut.setPreferredSize(new Dimension(300, 45));
                    ut.setFont( new Font("Times New Roman",Font.BOLD,20));
                    ut.setForeground(new Color(255,255,255).brighter());
                    ut.setBackground(new Color(3, 59, 90).brighter());

                    JTextArea ut1 = new JTextArea();
                    ut1.setPreferredSize(new Dimension(600, 80));
                    ut1.setLineWrap(true);

                    JTextArea ut2 = new JTextArea();
                    ut2.setPreferredSize(new Dimension(600, 80));
                    ut2.setLineWrap(true);

                    JTextArea t4 = new JTextArea();
                    t4.setPreferredSize(new Dimension(600, 80));
                    t4.setLineWrap(true);

                    JButton test1 = new JButton("Updated Test ");
                    test1.setPreferredSize(new Dimension(300, 45));
                    test1.setFont( new Font("Times New Roman",Font.BOLD,20));
                    test1.setForeground(new Color(255,255,255).brighter());
                    test1.setBackground(new Color(3, 59, 90).brighter());
                    tr.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            t1.setText(" Trapdoor1  is " + Tw1.toString());
                            t2.setText(" Trapdoor2 is " + Tw2.toString());
                        }
                    });
                    test.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            t3.setText(e1.toString());
                            t3.setLineWrap(true);
                        }
                    });
                    ut.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            ut1.setText("Update trapdoor1:"+utw1.toString());
                            t3.setLineWrap(true);
                            ut2.setText("Update trapdoor2:"+utw2.toString());
                            t3.setLineWrap(true);
                        }
                    });
                    test1.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            t4.setText(UE1.toString());
                            t4.setLineWrap(true);
                        }
                    });
                    panel3.add(send);
                    panel3.add(receiver);
                    panel3.add(t1);
                    panel3.add(ut1);
                    panel3.add(t2);
                    panel3.add(ut2);
                    panel3.add(t3);
                    panel3.add(t4);
                    panel3.add(tr);
                    panel3.add(test);
                    panel3.add(ut);
                    panel3.add(test1);

                    frame2.add(panel3);
                    frame2.setVisible(true);

                }
            });

            panel1.add(l1);
            panel1.add(lc1);
            panel1.add(l2);
            panel1.add(lc2);
            panel1.add(l3);
            panel1.add(lc3);
            panel1.add(l4);
            panel1.add(lc4);
            panel1.add(l5);
            panel1.add(lc5);
            panel1.add(enc);
            panel1.add(t);

            frame1.add(panel1);
            frame1.setVisible(true);

        }
    });

    add(panel);
    setVisible(true);
        //updated test ends here
    }
    public static void main(String[] args) {
    new Main();
}
}