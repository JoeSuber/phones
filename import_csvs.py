from app import import_all_sheets

""" run from prompt to import all the local csv data (that isn't already in the local db) 
    The word 'newsheet' must be in the title of each .csv file for it to be included in the list of targets 
    
    example:
    $ python import_all_sheets.py
    
    """

if __name__  == "__main__":
    import_all_sheets()
