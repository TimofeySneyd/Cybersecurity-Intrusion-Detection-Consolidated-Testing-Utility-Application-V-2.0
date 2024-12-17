# Cybersecurity-Intrusion-Detection-Consolidated-Testing-Utility-Application-V-2.0
Cybersecurity Intrusion Detection &amp; Consolidated Testing Utility Application for Network, Web and Application-Level Threats
1. Introduction

This Advanced Network Security Tool is a Ruby-based application that integrates multiple cybersecurity functionalities,
 such as network monitoring, web vulnerability scanning, ARP spoof detection, SQL injection testing, and more.

This guide will walk you through setting up the required environment and dependencies to run the tool successfully on your system.


2. System Requirements

Before running the tool, ensure your system meets the following requirements:

Operating System: Windows (Tested on Windows 10/11)
Ruby Version: Ruby 3.3 or higher
(Ensure Ruby is installed and configured on your system)
Command Prompt: Required for running the tool from the terminal.



3. Tool Location

Ensure the source file advanced_network_security_tool.rb is stored in the following directory:

C:\Ruby33\PROJECTS or any other path where you store the project/tool

cd C:\Ruby33\PROJECTS
dir C:\Ruby33\PROJECTS (or other path name of where you have stored your ruby project and files etc)



4. Setup Instructions


Step 1: Install Ruby

Download and install Ruby from the official website: https://rubyinstaller.org/.
During installation, select "Add Ruby to PATH". This ensures Ruby commands can be executed globally.


Step 2: Install Required Gems

The following Ruby gems are required to run the tool. Install them using the gem command in the Command Prompt.


Open the Command Prompt and run these commands one by one:

gem install colorize
gem install net-ping
gem install json
gem install nokogiri
gem install selenium-webdriver
gem install net-ssh
gem install httparty



Description of Gems:

colorize: Adds colorized output to the terminal.
net-ping: Provides ping functionality.
json: Handles JSON data for saving and loading.
nokogiri: Parses and analyzes HTML/XML content.
selenium-webdriver: Required for automating web scans and testing.
net-ssh: Provides SSH client capabilities.
httparty: Makes HTTP requests to test web vulnerabilities.



Step 3: Configure ChromeDriver for Selenium


Download ChromeDriver:
Visit ChromeDriver Download Page.
Match the ChromeDriver version with your installed Google Chrome browser version.


Add ChromeDriver to PATH:

Extract the downloaded chromedriver.exe file.
Move it to a directory, e.g., C:\Ruby33\TOOLS.

Add this directory to the system's PATH variable:

Go to Control Panel > System > Advanced System Settings > Environment Variables.
Add C:\Ruby33\TOOLS to the PATH variable.



5. Running the Tool

Open the Command Prompt.

Navigate to the tool's directory:

cd C:\Ruby33\PROJECTS

Run the tool using Ruby:

ruby advanced_network_security_tool.rb

Follow the on-screen instructions to use various functionalities.



6. Example of Usage

Step 1: Run the tool just as was showed in previous part of instruction #5.
Step 2: Enter the menu option number (e.g., 1 for "Display Network Configuration").
Step 3: Provide inputs as prompted (e.g., target URL, IP address).
Step 4: Review the results displayed in the terminal.



7. Troubleshooting

Error: Command Not Recognized: Ensure Ruby and ChromeDriver paths are properly set in the system's PATH variable.
Missing Gem Error: Run gem install <gem_name> to install missing gems.
ChromeDriver Compatibility: Verify that the ChromeDriver version matches your Chrome browser version.
