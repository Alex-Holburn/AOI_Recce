############################################################################################
# Program/Script Title: AOI_Recce.py
#
# Program/Script Version: 1.0
#
# Program/Script Purpose: The purpose of this script is to examine the .L5X
#                         export of an Add-On Instruction [AOI] from a
#                         a Studio5000 Project and return HVT information
#                         such as engineering workstation names, user names,
#                         Company Names, IDE Versions, and tag information.
#
# Special Note: Don't be an asshole and use this to plan unauthorized intrusions.
#               this is ademonstration tool to stress the need to sanitize identifying
#               information from program export files that could give an attacker
#               an advantage. Launching an attack can cause loss to life and limb.
#               That's totally not cool on and the same level as swatting people.
#
# Employment Note: I'm looking for an ICS Cyber Security Role, if you like this
#                  utility and have one, feel free to reach out. 
#
# Program/Script Author: Alex Holburn https://www.alexholburn.com
#
# License: MIT License. Copyright 2021, Alex Holburn https://www.alexholburn.com
#
############################################################################################

# -----------------------------------BEGIN LIBRARY IMPORTS---------------------------------

from platform import system
import os
import tkinter as main
import tkinter.filedialog
from PIL import ImageTk, Image
import webbrowser
import xml.etree.ElementTree as ET
import subprocess

# -----------------------------------END LIBRARY IMPORTS-----------------------------------

# -----------------------------------BEGIN VARIABLE DECLARATIONS---------------------------

operating_system = system()
dirName = os.path.dirname(__file__)  # Current directory
utilityImage = os.path.join(dirName, r'resources\AOI_Recce_Text.png')
icoImage = os.path.join(dirName, r'resources\icon.ico')  # .ico image path
logoImage = os.path.join(dirName, r'resources\AlexHolburnLogo.png')  # logo image for shameless self promotion


# -----------------------------------BEGIN FUNCTION DEFINITIONS----------------------------

def extract_between(string, delim_1, delim_2):  # The purpose of this function is to extract the middle of a string.
    pos_delim_1 = string.find(delim_1)  # Find the position of the 1st delimiter.
    if pos_delim_1 == -1:  # Validate the string
        return ""

    pos_delim_2 = string.rfind(delim_2)  # Find the position of the 2nd delimiter.
    if pos_delim_2 == -1:
        return ""  # Validate the string

    adjusted_pos_delim_1 = pos_delim_1 + len(delim_1)  # Find the start position of the second slice of the string.
    if adjusted_pos_delim_1 >= pos_delim_2:  # Validate the processed string.
        return ""
    return string[adjusted_pos_delim_1:pos_delim_2]  # Return the processed string.


def extract_before(string, delim):  # Extract the part of a string before a delimiter
    pos_delim = string.find(delim)  # Find the position of the delimiter.
    if pos_delim == -1:  # Validate the string
        return ""
    return string[0:pos_delim]  # Return the processed string.


def extract_after(string, delim):  # Extract the part of a string after a delimiter.
    pos_delim = string.rfind(delim)  # Find the position of the delimiter
    if pos_delim == -1:
        return ""  # Validate the string
    adjusted_pos_delim = pos_delim + len(delim)  # Find the start position of the second slice of the string.
    if adjusted_pos_delim >= len(string):
        return ""  # Validate the string
    return string[adjusted_pos_delim:]  # Return the processed string.


def static_description_text():  # Function to paint static description text.
    description1 = main.Label(root, text='This utility is used to identify targeting information '
                                         'from an AOI export [.L5X] to include Engineering Workstations,',
                              fg='black', font=('Segoe', 8))
    canvas1.create_window(275, 50, window=description1)

    description2 = main.Label(root, text='usernames, Company Names, input/output tag information and more. '
                                         'MITRE ATT&CK ICS Technique numbers this',
                              fg='black', font=('Segoe', 8))
    canvas1.create_window(275, 66, window=description2)

    description3 = main.Label(root, text='tool generates target data for include T0818, T0865, and T0802. '
                                         'This tool targets Studio 5000 AOI exports [.L5X]',
                              fg='black', font=('Segoe', 8))
    canvas1.create_window(275, 82, window=description3)


def static_status_text():  # Function to paint static status text.
    status1 = main.Label(root, text='Program Status:', fg='black', bg='White', font=('Segoe', 8,))
    canvas1.create_window(52, 186, window=status1)

    status2 = main.Label(root, text='Waiting for user input.', fg='black', bg='White', font=('Segoe', 8,))
    canvas1.create_window(67, 210, window=status2)


def browse_file():  # Define the file dialog with all files and .L5X extensions. Also updates selected file text.
    global target_l5x  # Used as a global variable to get the filepath out of the function. Should update this to OOP.

    target_file = main.filedialog.askopenfilename(initialdir="/", title="Select A File",
                                                  filetype=(("Logix 5000 Export", "*.L5X"), ("All Files", "*.*")))

    selected_file = main.Label(root, text=target_file, fg='black', bg='white', font=('Segoe', 8))
    canvas1.create_window(215, 117, window=selected_file)

    target_l5x = target_file


def browse_button():  # Generates the browse button, on click, this guy calls browse_file.
    browse_file_button = main.Button(text='Select .L5X File', command=browse_file, )
    canvas1.create_window(475, 117, window=browse_file_button)


def analyze_file():  # Saves the file to a location of the users choice, and kicks off the analysis.
    files = [('Text File', '*.txt'), ('All Files', '*.*')]
    file = main.filedialog.asksaveasfile(filetypes=files, defaultextension=files)  # We create the output text file here

    tree = ET.parse(target_l5x)  # Parse the target file
    xml_root = tree.getroot()  # Find the root tag of the XML
    xml_root_tag = xml_root.tag  # Extract only the tag name from root

    if xml_root_tag == "RSLogix5000Content":  # Check if the root is "RSLogix5000Content".
        xml_targettype_tag = xml_root.attrib['TargetType']

        status3 = main.Label(root, text='XML Content Type Check Status: OK (RSLogix5000Content).', fg='black',
                             bg='White',
                             font=('Segoe', 8,))
        canvas1.create_window(160, 226, window=status3)

        if xml_targettype_tag == "AddOnInstructionDefinition":  # Check that the export type is an AOI and process file.
            # We are setting the variables used to generate the analysis data here. 
            aoi_name = "AOI Name: " + xml_root.attrib['TargetName']
            aoi_revision = "AOI Revision: " + xml_root.find(".//AddOnInstructionDefinition").get('Revision')
            aoi_vendor = "AOI Vendor: " + xml_root.find(".//AddOnInstructionDefinition").get('Vendor')
            aoi_logix_version = "AOI Developed in Logix Version: " + xml_root.find(".//AddOnInstructionDefinition").get(
                'SoftwareRevision')
            engineering_info1 = xml_root.find(".//AddOnInstructionDefinition").get('CreatedBy')
            engineering_workstation1 = "Engineering Workstation #1: " + extract_before(engineering_info1, "\\")
            engineering_user1 = "Engineering User #1: " + extract_after(engineering_info1, "\\")
            engineering_info2 = xml_root.find(".//AddOnInstructionDefinition").get('EditedBy')
            engineering_workstation2 = "Engineering Workstation #2: " + extract_before(engineering_info2, "\\")
            engineering_user2 = "Engineering User #2: " + extract_after(engineering_info2, "\\")
            controller_name = "Controller Name: " + xml_root.find(".//Controller").get('Name')
            logix_version = "Logix 5000 Version: " + xml_root.attrib['SoftwareRevision']
            owner = xml_root.attrib['Owner']
            user = "Licensed User: " + extract_before(owner, ",")
            company = "Company: " + extract_after(owner, ", ")

            status5 = main.Label(root, text='Export Target Type Check Status: OK (AddOnInstructionDefinition)',
                                 fg='black', bg='White', font=('Segoe', 8,))
            canvas1.create_window(174, 242, window=status5)

            status6 = main.Label(root, text='Generating AOI Analysis.',
                                 fg='black', bg='White', font=('Segoe', 8,))
            canvas1.create_window(75, 258, window=status6)
                                                     
            # Begin Generation of the AOI Analysis Text File
            analysis_file = file
            analysis_file.write("********************************************************* \n")
            analysis_file.write("Automated Analysis Performed By AOI Recce Version 1.0 \n")
            analysis_file.write("********************************************************* \n")
            analysis_file.write("\n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("***********General AOI Information*********** \n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("\n")
            analysis_file.write(aoi_name + "\n")
            analysis_file.write(aoi_revision + "\n")
            analysis_file.write(aoi_vendor + "\n")
            analysis_file.write(aoi_logix_version + "\n")
            analysis_file.write(aoi_vendor + "\n")
            analysis_file.write("\n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("******Probable Engineering Workstations****** \n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("\n")
            analysis_file.write(engineering_workstation1 + "\n")
            analysis_file.write(engineering_user1 + "\n")
            analysis_file.write(engineering_workstation2 + "\n")
            analysis_file.write(engineering_user2 + "\n")
            analysis_file.write("\n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("*********Logix 5000 IDE Information********** \n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("\n")
            analysis_file.write(controller_name + "\n")
            analysis_file.write(logix_version + "\n")
            analysis_file.write(user + "\n")
            analysis_file.write(company + "\n")
            analysis_file.write("\n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("*********AOI Target Tag Information********** \n")
            analysis_file.write("********************************************* \n")
            analysis_file.write("\n")

            for child in xml_root.find(".//Parameters"):
                str1 = str(child.attrib)
                analysis_file.write(str1)
                analysis_file.write("\n")
                analysis_file.write("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
                analysis_file.write("\n")

            analysis_file.write("\n")
            analysis_file.close()

            status7 = main.Label(root, text='AOI Analysis Complete, Please Exit.',
                                 fg='black', bg='White', font=('Segoe', 8,))
            canvas1.create_window(100, 274, window=status7)


        else:
            status5 = main.Label(root, text='Export Target Type Check Status: FAIL (AddOnInstructionDefinition)',
                                 fg='black', bg='White', font=('Segoe', 8,))
            canvas1.create_window(178, 242, window=status5)

            status4 = main.Label(root, text='Process Aborted.', fg='black', bg='White', font=('Segoe', 8,))
            canvas1.create_window(56, 258, window=status4)

    else:
        status3 = main.Label(root, text='XML Content Type Check Status: FAIL (RSLogix5000Content).', fg='black',
                             bg='White',
                             font=('Segoe', 8,))
        canvas1.create_window(164, 226, window=status3)

        status4 = main.Label(root, text='Process Aborted.', fg='black', bg='White', font=('Segoe', 8,))
        canvas1.create_window(56, 242, window=status4)


def analyze_button():  # Generates the analyze button, on click this guy calls analyze_file.
    analyze_file_button = main.Button(text='Analyze File', command=analyze_file, )
    canvas1.create_window(275, 155, window=analyze_file_button)


def callback(url):  # callback function. This guy lets us use URLs in an application.
    webbrowser.open_new(url)


# -----------------------------------END FUNCTION DEFINITIONS------------------------------

root = main.Tk()

# Set The Icon
root.iconbitmap(icoImage)

# Paint the canvas
canvas1 = main.Canvas(root, width=550, height=400)
canvas1.winfo_toplevel().title("AOI Recce Version 1.0")
canvas1.pack()

# Create Status Box
canvas1.create_rectangle(10, 175, 540, 300, fill="white")

# Create Selected Filepath Box
canvas1.create_rectangle(10, 105, 425, 128, fill="white")

# Paint The Utility Logo
loadUtilityLogo = loadLogo = ImageTk.PhotoImage(Image.open(utilityImage))
canvas1.create_image(275, 25, image=loadLogo)

# Generate the Static Text
static_description_text()

# Generate Buttons and Option Radio Selections
browse_button()
analyze_button()

# Generate Static Status Text
static_status_text()

# Shameless Self Marketing (Psssst, I'm looking for a job in ICS cybersecurity!)
loadLogo = ImageTk.PhotoImage(Image.open(logoImage))
canvas1.create_image(250, 360, image=loadLogo)

link1 = main.Label(root, text="https://alexholburn.com/", fg="blue", font=('Segoe', 8, 'underline'), cursor="hand2")
link1.pack()
link1.bind("<Button-1>", lambda e: callback("https://alexholburn.com/"))

# Loop so the window appears
root.mainloop()
