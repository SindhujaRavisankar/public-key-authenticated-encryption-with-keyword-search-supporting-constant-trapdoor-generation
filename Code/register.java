import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
    public class register extends JFrame implements ActionListener {
        // form components
        private JLabel reg, nameLabel, emailLabel, passwordLabel, confirmLabel;
        private JTextField nameField, emailField;
        private JPasswordField passwordField, confirmField;
        private JButton registerButton, clearButton, cancelButtuon;

        public register() {
            setTitle("Registration Form");
            setBackground(new Color(124, 230, 12));
            // create components
            reg = new JLabel("Register");
            reg.setFont(new Font("Times New Roman", Font.BOLD, 26));
            nameLabel = new JLabel("Name:");
            emailLabel = new JLabel("Email:");
            passwordLabel = new JLabel("Password:");
            confirmLabel = new JLabel("Confirm Password:");
            nameField = new JTextField(20);
            emailField = new JTextField(20);
            passwordField = new JPasswordField(20);
            confirmField = new JPasswordField(20);
            registerButton = new JButton("Register");
            clearButton = new JButton("Clear");
            cancelButtuon = new JButton("back");

            // set layout
            setLayout(new GridBagLayout());
            setBackground(Color.MAGENTA);
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(5, 5, 5, 5);
            gbc.gridx = 1;
            gbc.gridy = 0;
            add(reg, gbc);
            gbc.gridx = 0;
            gbc.gridy = 1;
            add(nameLabel, gbc);
            gbc.gridx = 1;
            gbc.gridy = 1;
            add(nameField, gbc);
            gbc.gridx = 0;
            gbc.gridy = 2;
            add(emailLabel, gbc);
            gbc.gridx = 1;
            gbc.gridy = 2;
            add(emailField, gbc);
            gbc.gridx = 0;
            gbc.gridy = 3;
            add(passwordLabel, gbc);
            gbc.gridx = 1;
            gbc.gridy = 3;
            add(passwordField, gbc);
            gbc.gridx = 0;
            gbc.gridy = 4;
            add(confirmLabel, gbc);
            gbc.gridx = 1;
            gbc.gridy = 4;
            add(confirmField, gbc);
            gbc.gridx = 0;
            gbc.gridy = 5;
            add(registerButton, gbc);
            gbc.gridx = 1;
            gbc.gridy = 5;
            add(clearButton, gbc);
            gbc.gridx = 2;
            gbc.gridy = 5;
            add(cancelButtuon, gbc);

            // add action listeners
            registerButton.addActionListener(this);
            clearButton.addActionListener(this);
            cancelButtuon.addActionListener(this);

            // set size and visibility
            setSize(500, 500);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setVisible(true);
        }

        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == registerButton) {
                // validate form input
                String name = nameField.getText().trim();
                String email = emailField.getText().trim();
                char[] password = passwordField.getPassword();
                char[] confirm = confirmField.getPassword();
                if (name.isEmpty() || email.isEmpty() || password.length == 0 || confirm.length == 0) {
                    JOptionPane.showMessageDialog(this, "Please fill out all fields.");
                } else if (!String.valueOf(password).equals(String.valueOf(confirm))) {
                    JOptionPane.showMessageDialog(this, "Passwords do not match.");
                } else {
                    // write data to CSV file
                    try {
                        BufferedWriter writer = new BufferedWriter(new FileWriter("users.csv", true));
                        writer.write(name + "," + email + "," + String.valueOf(password));
                        writer.newLine();
                        writer.close();
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(this, "Error writing to file: " + ex.getMessage());
                    }
                    JOptionPane.showMessageDialog(this, "Registration successful.");
                    nameField.setText("");
                    emailField.setText("");
                    passwordField.setText("");
                    confirmField.setText("");
                    login log = new login();
                    log.setVisible(true);
                }
            } else if (e.getSource() == clearButton) {
                // clear form input
                JOptionPane.showMessageDialog(this, "Registration cancelled");
                nameField.setText("");
                emailField.setText("");
                passwordField.setText("");
                confirmField.setText("");
            } else if (e.getSource() == cancelButtuon) {
                home hm = new home();
                hm.setVisible(true);
                setVisible(false);
            }
        }
    }