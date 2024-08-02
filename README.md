# Jupyter-Password-Cracking-Framework
A JupyterLab notebook with functionality to help manage password cracking sessions. Specifically geared towards helping with password cracking competitions.

**Warning**: This is very early in development. It's usable, but treat it as an early alpha release. Which is another way of saying make sure you back up your potfiles before loading them in this framework, and there may still be some drastic changes on the backend. Also the functionality is fairly limited right now but I'm hopeful I can make progress on this.

## References
I wrote three blog posts talking about how to use JupyterLab to aid in compeating in the CMIYC2023 Password Cracking Competition. These posts use a very early version of this framework. Since then, I've developed a backend for the framework to make keeping track of hashes, plaintext, and metadata easier, but the blogposts can give you a good idea for how this framework can be used.

- [Part 1](https://reusablesec.blogspot.com/2023/08/using-jupyterlab-to-manage-password.html)
- [Part 2](https://reusablesec.blogspot.com/2023/08/using-jupyterlab-to-manage-password_22.html)
- [Part 3](https://reusablesec.blogspot.com/2023/08/hashcat-tips-and-tricks-for-hacking.html)

## Installing JupyterLab


To install JupyterLab and required libraires for this framework (such as pyyaml) you can use the included **requirements.txt** file. E.g.
- pip3 install -r requirements.txt

Note: On some sytems, (such as Ubuntu), it doesn't allow you by default to install tools globably using pip3. Threfore to get Jupyter Lab to actually install you may need to run a command such as:
- sudo apt install python3-jupyterlab

Another option would be to make sure the local directory that JupyterLabs is installed to is in your environmental $PATH variable.

Note 2: One challenge I found is that I couldn't run Jupyter lab on Python3.6. It seems to need at least Python3.7.

## Running the Framework:
From a shell in the install directory run:
- jupyter lab

This will give you a local webpage URL you can then browse to and view the actual framework

## Framework Notebooks:
There currently are two example notebooks. I'm looking to add more examples as I build this out containing tutorials and examples from past password cracking competitions.

The current notebooks are:
- Getting_Started.ipynmb: This will eventually have information about the backend python classes as well as brief descriptions of the other notebooks. It's mostly just a placeholder right now.

- CMIYC_2023_Example.ipynb: This is the main example notebook right now. I'm including a **very limited** version of the challenge files from the CMIYC2023 street team competition, but I recommend getting the full file from Korelogic if you really want to play around with this notebook.
