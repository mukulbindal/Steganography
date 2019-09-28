# Steganography
create a folder steganography_social_media and move all the files in it

Open cmd in root folder where the above folder exists

The file structure shoud look like -->  root -> steganography_social_media -> {all-files-here}

Run the following commands:

pip install virtualenv                        // to install virtual environment

virtualenv venv                               // to create virtual environment in current directory

venv\scripts\activate                         // to enable virtual environment

cd <folder-name-where-requirements.txt-exists>

pip install -r requirements.txt               // install all libraries

python manage.py makemigrations

python manage.py migrate                      // to migrate the database

python manage.py runserver                    // to start the application


