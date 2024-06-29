import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.Image;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class home extends JFrame{
    // form components
    private JLabel w1, w2, image, email, pass;

    private JTextField t1;
    private JPasswordField pt1;
    private JButton reg, log;

    public home() {
        setTitle("PAUKS");
        setSize(getMaximumSize());
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        panel.setBackground(Color.CYAN);
        JLabel w1 = new JLabel("Public Key Authenticated Encryption with keyword search supporting Constant Trapdoor Generation");
        w1.setFont(new Font("Times New Roman",Font.BOLD,26));
        w1.setPreferredSize(new Dimension(1150,100));

        JButton reg = new JButton("Register");
        reg.setPreferredSize(new Dimension(400,30));
        reg.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                register reg = new register();
                reg.setVisible(true);
                setVisible(false);
            }
        });

        JButton log = new JButton("Login");
        log.setPreferredSize(new Dimension(400,30));
        panel.add(w1);
        panel.add(Box.createRigidArea(new Dimension(10, 0)));
        log.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                    login log1 = new login();
                    log1.setVisible(true);
                    setVisible(false);
            }
        });
        //add(image);

        //set text field to panel
        panel.add(reg);
        panel.add(log);

        //set border to panel
        // add(newPanel, BorderLayout.CENTER);

        add(panel);
        setVisible(true);
    }
    public static void main(String args[]){
        new home();
    }
    }

