import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QGridLayout, QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QFileDialog, QGroupBox, QRadioButton, QMessageBox, 
                             QCheckBox, QTabWidget, QScrollArea)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon

class AnsibleInventoryCreator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ansible Inventory Creator")
        self.setGeometry(100, 100, 900, 700)
        
        # Main widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.hosts_tab = QWidget()
        self.settings_tab = QWidget()
        self.preview_tab = QWidget()
        
        self.tabs.addTab(self.hosts_tab, "Hosts")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.preview_tab, "Preview")
        
        # Setup each tab
        self.setup_hosts_tab()
        self.setup_settings_tab()
        self.setup_preview_tab()
        
        main_layout.addWidget(self.tabs)
        
        # Buttons at the bottom
        buttons_layout = QHBoxLayout()
        
        self.save_button = QPushButton("Save Inventory")
        self.save_button.clicked.connect(self.save_inventory)
        self.save_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 8px;")
        
        self.generate_button = QPushButton("Generate Inventory")
        self.generate_button.clicked.connect(self.generate_inventory)
        self.generate_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; padding: 8px;")
        
        buttons_layout.addWidget(self.generate_button)
        buttons_layout.addWidget(self.save_button)
        main_layout.addLayout(buttons_layout)
        
        self.setCentralWidget(central_widget)
        
        # Initialize class variables
        self.hosts = []
        self.inventory_content = ""
        
    def setup_hosts_tab(self):
        hosts_layout = QVBoxLayout(self.hosts_tab)
        
        # Instructions
        instructions = QLabel("Enter IP addresses or hostnames (one per line):")
        instructions.setFont(QFont("Arial", 10, QFont.Bold))
        hosts_layout.addWidget(instructions)
        
        # Host input area
        self.hosts_input = QTextEdit()
        self.hosts_input.setPlaceholderText("Example:\n192.168.1.100\nserver1.example.com\n10.0.0.1")
        hosts_layout.addWidget(self.hosts_input)
        
        # Host type selection
        type_group = QGroupBox("Host Type")
        type_layout = QHBoxLayout()
        
        self.linux_radio = QRadioButton("Linux")
        self.windows_radio = QRadioButton("Windows")
        self.linux_radio.setChecked(True)
        
        type_layout.addWidget(self.linux_radio)
        type_layout.addWidget(self.windows_radio)
        type_group.setLayout(type_layout)
        
        hosts_layout.addWidget(type_group)
        
        # Batch import/export
        batch_group = QGroupBox("Batch Operations")
        batch_layout = QHBoxLayout()
        
        import_hosts_btn = QPushButton("Import Hosts from File")
        import_hosts_btn.clicked.connect(self.import_hosts)
        
        clear_hosts_btn = QPushButton("Clear All Hosts")
        clear_hosts_btn.clicked.connect(self.clear_hosts)
        
        batch_layout.addWidget(import_hosts_btn)
        batch_layout.addWidget(clear_hosts_btn)
        batch_group.setLayout(batch_layout)
        
        hosts_layout.addWidget(batch_group)
    
    def setup_settings_tab(self):
        settings_layout = QVBoxLayout(self.settings_tab)
        
        # Create a scroll area for settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        settings_content = QWidget()
        settings_content_layout = QVBoxLayout(settings_content)
        
        # Linux Settings
        linux_group = QGroupBox("Linux Settings")
        linux_layout = QGridLayout()
        
        linux_layout.addWidget(QLabel("Group Name:"), 0, 0)
        self.linux_group_name = QLineEdit("linux")
        linux_layout.addWidget(self.linux_group_name, 0, 1)
        
        linux_layout.addWidget(QLabel("SSH User:"), 1, 0)
        self.linux_ssh_user = QLineEdit("ansible")
        linux_layout.addWidget(self.linux_ssh_user, 1, 1)
        
        linux_layout.addWidget(QLabel("SSH Password Variable:"), 2, 0)
        self.linux_ssh_pass_var = QLineEdit("ansible_ssh_pass")
        linux_layout.addWidget(self.linux_ssh_pass_var, 2, 1)
        
        linux_layout.addWidget(QLabel("SSH Key File:"), 3, 0)
        self.linux_key_file = QLineEdit("~/.ssh/id_rsa")
        linux_layout.addWidget(self.linux_key_file, 3, 1)
        
        self.use_sudo = QCheckBox("Use sudo")
        self.use_sudo.setChecked(True)
        linux_layout.addWidget(self.use_sudo, 4, 0, 1, 2)
        
        linux_group.setLayout(linux_layout)
        settings_content_layout.addWidget(linux_group)
        
        # Windows Settings
        windows_group = QGroupBox("Windows Settings")
        windows_layout = QGridLayout()
        
        windows_layout.addWidget(QLabel("Group Name:"), 0, 0)
        self.windows_group_name = QLineEdit("windows")
        windows_layout.addWidget(self.windows_group_name, 0, 1)
        
        windows_layout.addWidget(QLabel("Connection Type:"), 1, 0)
        self.win_connection = QLineEdit("winrm")
        windows_layout.addWidget(self.win_connection, 1, 1)
        
        windows_layout.addWidget(QLabel("WinRM User:"), 2, 0)
        self.win_user = QLineEdit("administrator")
        windows_layout.addWidget(self.win_user, 2, 1)
        
        windows_layout.addWidget(QLabel("WinRM Password Variable:"), 3, 0)
        self.win_pass_var = QLineEdit("ansible_password")
        windows_layout.addWidget(self.win_pass_var, 3, 1)
        
        windows_layout.addWidget(QLabel("WinRM Port:"), 4, 0)
        self.win_port = QLineEdit("5985")
        windows_layout.addWidget(self.win_port, 4, 1)
        
        windows_layout.addWidget(QLabel("WinRM Transport:"), 5, 0)
        self.win_transport = QLineEdit("basic")
        windows_layout.addWidget(self.win_transport, 5, 1)
        
        self.win_skip_cert = QCheckBox("Skip Certificate Validation")
        self.win_skip_cert.setChecked(True)
        windows_layout.addWidget(self.win_skip_cert, 6, 0, 1, 2)
        
        windows_group.setLayout(windows_layout)
        settings_content_layout.addWidget(windows_group)
        
        # Vault Settings
        vault_group = QGroupBox("Ansible Vault Settings")
        vault_layout = QGridLayout()
        
        self.use_vault = QCheckBox("Use Ansible Vault for Passwords")
        vault_layout.addWidget(self.use_vault, 0, 0, 1, 2)
        
        vault_layout.addWidget(QLabel("Vault File Name:"), 1, 0)
        self.vault_file = QLineEdit("group_vars/all/vault.yml")
        vault_layout.addWidget(self.vault_file, 1, 1)
        
        vault_group.setLayout(vault_layout)
        settings_content_layout.addWidget(vault_group)
        
        # Additional Settings
        add_group = QGroupBox("Additional Settings")
        add_layout = QVBoxLayout()
        
        self.add_comments = QCheckBox("Add Comments to Inventory File")
        self.add_comments.setChecked(True)
        add_layout.addWidget(self.add_comments)
        
        self.use_yaml = QCheckBox("Use YAML Format (Instead of INI)")
        add_layout.addWidget(self.use_yaml)
        
        add_group.setLayout(add_layout)
        settings_content_layout.addWidget(add_group)
        
        # Set the scroll area widget
        scroll.setWidget(settings_content)
        settings_layout.addWidget(scroll)
        
    def setup_preview_tab(self):
        preview_layout = QVBoxLayout(self.preview_tab)
        
        # Preview area
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QFont("Courier New", 10))
        self.preview_text.setPlaceholderText("Your inventory file preview will appear here.\nClick 'Generate Inventory' to see it.")
        preview_layout.addWidget(self.preview_text)
    
    def import_hosts(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Hosts from File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    hosts = file.read()
                    # If there's existing content, add a newline
                    if self.hosts_input.toPlainText():
                        self.hosts_input.append("\n" + hosts)
                    else:
                        self.hosts_input.setText(hosts)
                    QMessageBox.information(self, "Import Successful", f"Successfully imported hosts from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to import hosts: {str(e)}")
    
    def clear_hosts(self):
        reply = QMessageBox.question(self, "Clear Hosts", 
                                     "Are you sure you want to clear all hosts?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.hosts_input.clear()
    
    def generate_inventory(self):
        # Get host list
        hosts_text = self.hosts_input.toPlainText().strip()
        if not hosts_text:
            QMessageBox.warning(self, "No Hosts", "Please enter at least one host IP or hostname.")
            return
            
        self.hosts = [host.strip() for host in hosts_text.split('\n') if host.strip()]
        
        # Generate inventory based on format
        if self.use_yaml.isChecked():
            self.generate_yaml_inventory()
        else:
            self.generate_ini_inventory()
            
        # Show the preview
        self.preview_text.setText(self.inventory_content)
        self.tabs.setCurrentIndex(2)  # Switch to preview tab
        
    def generate_ini_inventory(self):
        content = []
        
        # Add comments if enabled
        if self.add_comments.isChecked():
            content.append("# Ansible Inventory File")
            content.append("# Generated by Ansible Inventory Creator")
            content.append("")
        
        # Determine group name based on host type
        group_name = self.windows_group_name.text() if self.windows_radio.isChecked() else self.linux_group_name.text()
        
        # Add hosts section
        content.append(f"[{group_name}]")
        for host in self.hosts:
            content.append(host)
        content.append("")
        
        # Add group vars section
        content.append(f"[{group_name}:vars]")
        
        if self.windows_radio.isChecked():
            # Windows vars
            content.append(f"ansible_connection={self.win_connection.text()}")
            content.append(f"ansible_user={self.win_user.text()}")
            if not self.use_vault.isChecked():
                content.append(f"{self.win_pass_var.text()}=CHANGE_ME")
            content.append(f"ansible_winrm_port={self.win_port.text()}")
            content.append(f"ansible_winrm_transport={self.win_transport.text()}")
            if self.win_skip_cert.isChecked():
                content.append("ansible_winrm_server_cert_validation=ignore")
        else:
            # Linux vars
            content.append(f"ansible_user={self.linux_ssh_user.text()}")
            if not self.use_vault.isChecked():
                content.append(f"{self.linux_ssh_pass_var.text()}=CHANGE_ME")
            content.append(f"ansible_ssh_private_key_file={self.linux_key_file.text()}")
            if self.use_sudo.isChecked():
                content.append("ansible_become=true")
                content.append("ansible_become_method=sudo")
        
        # Add vault info if enabled
        if self.use_vault.isChecked() and self.add_comments.isChecked():
            content.append("")
            content.append("# Note: Passwords are stored in the vault file:")
            content.append(f"# {self.vault_file.text()}")
            
        self.inventory_content = "\n".join(content)
        
    def generate_yaml_inventory(self):
        content = []
        
        # Add comments if enabled
        if self.add_comments.isChecked():
            content.append("# Ansible Inventory File (YAML format)")
            content.append("# Generated by Ansible Inventory Creator")
            content.append("")
        
        # Determine group name based on host type
        group_name = self.windows_group_name.text() if self.windows_radio.isChecked() else self.linux_group_name.text()
        
        content.append("all:")
        content.append("  children:")
        content.append(f"    {group_name}:")
        content.append("      hosts:")
        
        # Add hosts
        for i, host in enumerate(self.hosts):
            content.append(f"        host{i+1}:")
            content.append(f"          ansible_host: {host}")
        
        # Add group vars
        content.append("      vars:")
        
        if self.windows_radio.isChecked():
            # Windows vars
            content.append(f"        ansible_connection: {self.win_connection.text()}")
            content.append(f"        ansible_user: {self.win_user.text()}")
            if not self.use_vault.isChecked():
                content.append(f"        {self.win_pass_var.text()}: CHANGE_ME")
            content.append(f"        ansible_winrm_port: {self.win_port.text()}")
            content.append(f"        ansible_winrm_transport: {self.win_transport.text()}")
            if self.win_skip_cert.isChecked():
                content.append("        ansible_winrm_server_cert_validation: ignore")
        else:
            # Linux vars
            content.append(f"        ansible_user: {self.linux_ssh_user.text()}")
            if not self.use_vault.isChecked():
                content.append(f"        {self.linux_ssh_pass_var.text()}: CHANGE_ME")
            content.append(f"        ansible_ssh_private_key_file: {self.linux_key_file.text()}")
            if self.use_sudo.isChecked():
                content.append("        ansible_become: true")
                content.append("        ansible_become_method: sudo")
        
        # Add vault info if enabled
        if self.use_vault.isChecked() and self.add_comments.isChecked():
            content.append("")
            content.append("# Note: Passwords are stored in the vault file:")
            content.append(f"# {self.vault_file.text()}")
            
        self.inventory_content = "\n".join(content)
        
    def save_inventory(self):
        # Check if inventory has been generated
        if not self.inventory_content:
            QMessageBox.warning(self, "No Inventory", "Please generate the inventory first.")
            return
            
        # Get file path
        default_ext = "yaml" if self.use_yaml.isChecked() else "ini"
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Inventory File", 
            f"inventory.{default_ext}", 
            f"Ansible Inventory (*.{default_ext});;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(self.inventory_content)
                QMessageBox.information(self, "Save Successful", f"Inventory saved to {file_path}")
                
                # If vault is enabled, offer to create vault file
                if self.use_vault.isChecked():
                    reply = QMessageBox.question(
                        self, 
                        "Create Vault File", 
                        "Do you want to create a template vault file?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if reply == QMessageBox.Yes:
                        self.create_vault_template(file_path)
                        
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save inventory: {str(e)}")
                
    def create_vault_template(self, inventory_path):
        try:
            import os
            
            # Get directory of inventory file
            inventory_dir = os.path.dirname(inventory_path)
            vault_path = os.path.join(inventory_dir, self.vault_file.text())
            
            # Create directories if they don't exist
            os.makedirs(os.path.dirname(vault_path), exist_ok=True)
            
            # Create vault template
            vault_content = []
            vault_content.append("---")
            vault_content.append("# Ansible Vault File")
            vault_content.append("# IMPORTANT: Encrypt this file with: ansible-vault encrypt this_file.yml")
            vault_content.append("")
            
            if self.windows_radio.isChecked():
                vault_content.append(f"{self.win_pass_var.text()}: 'your_secure_password'")
            else:
                vault_content.append(f"{self.linux_ssh_pass_var.text()}: 'your_secure_password'")
                
            # Write to file
            with open(vault_path, 'w') as file:
                file.write("\n".join(vault_content))
                
            QMessageBox.information(
                self, 
                "Vault Template Created", 
                f"Vault template created at {vault_path}\n\nRemember to encrypt it with:\nansible-vault encrypt {vault_path}"
            )
            
        except Exception as e:
            QMessageBox.warning(self, "Vault Creation Error", f"Failed to create vault template: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = AnsibleInventoryCreator()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()