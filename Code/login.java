import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;

public class login extends JFrame implements ActionListener {
    // form components
    private JLabel emailLabel, passwordLabel, image, login;
    private JTextField emailField;
    private JPasswordField passwordField;
    private JButton loginButton, clearButton;

    public login() {
        setTitle("Login Form");

        // create components
        login = new JLabel("Login");
        login.setFont(new Font("Times New Roman",Font.BOLD,26));
        emailLabel = new JLabel("Email:");
        passwordLabel = new JLabel("Password:");
        emailField = new JTextField(20);
        passwordField = new JPasswordField(20);
        loginButton = new JButton("Login");
        clearButton = new JButton("Cancel");
        // set layout
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 1;
        gbc.gridy = 0;
        add(login, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        add(emailLabel, gbc);
        gbc.gridx = 1;
        gbc.gridy = 1;
        add(emailField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 2;
        add(passwordLabel, gbc);
        gbc.gridx = 1;
        gbc.gridy = 2;
        add(passwordField, gbc);
        gbc.gridx = 0;
        gbc.gridy = 3;
        add(loginButton, gbc);
        gbc.gridx = 1;
        gbc.gridy = 3;
        add(clearButton,gbc);

        // add action listeners
        loginButton.addActionListener(this);
        clearButton.addActionListener(this);

        // set size and visibility
        setSize(600, 550);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == loginButton) {
            // validate form input
            String email = emailField.getText().trim();
            char[] password = passwordField.getPassword();
            if (email.isEmpty() || password.length == 0) {
                JOptionPane.showMessageDialog(this, "Please enter your email and password.");
            } else {
                // check user credentials against CSV file
                boolean found = false;
                try {
                    FileReader reader = new FileReader("users.csv");
                    BufferedReader bufferedReader = new BufferedReader(reader);
                    String line;
                    while ((line = bufferedReader.readLine()) != null) {
                        String[] parts = line.split(",");
                        if (parts[1].equals(email) && parts[2].equals(String.valueOf(password))) {
                            found = true;
                            break;
                        }
                    }
                    bufferedReader.close();
                    reader.close();
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage());
                }
                if (found) {
                    JOptionPane.showMessageDialog(this, "Login Successfully");
                    Main M1 = new Main();
                    M1.setVisible(true);
                    setVisible(false);
                } else {
                    JOptionPane.showMessageDialog(this, "Invalid email or password.");
                }
            }
        } else if (e.getSource() == clearButton) {
            // clear form input
            emailField.setText("");
            passwordField.setText("");
            home h = new home();
            h.setVisible(true);
            setVisible(false);
        }
    }
}

