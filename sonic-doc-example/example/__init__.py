"""This is an example of of how to document a module in sonic-mgmt.

All modules should begin with a one line summary, followed by further description if necessary.  If you are documenting a test file, this is a good place to briefly describe what type of behavior you are testing.

Note:
    You can add specific notes regarding usage, limitations, etc. as well.

Example:
    Usage examples are also encouraged, especially for test cases that have a lot of input parameters or specific setup requirements. You can even include code snippets like so::
        
        $ pytest -v --example-param "SONiC is great!" test_example.py

Todo:
    * Future improvements can be added as module-level todos
    * Also an appropriate place to note future test cases
"""

THIS_IS_A_CONSTANT = 202006
"""Module level variables should be documented like so.

Note that only public facing variables need to be documented. If you wish for a variable to be private, please indicate so by adding a double underscore prefix as shown in the source.
"""

__PRIVATE_CONSTANT = 2
"""Note I can still add a comment to this variable and it will not be included in the documentation."""

def module_level_function_example(x, y):
    """This is an example of how to document a function with docstrings.

    Functions also begin with a one line summary, followed by additional description as appropriate.

    Caution:
        If your method performs a write operation on the DUT, PTF, or any other part of the system, it's helpful to include a note to the client. This is not required for test-case specific code, but will be enforced during code review for shared code.

    Args:
        x (int): The first argument.
            Note that descriptions can span multiple lines as long as following lines
            are indented.

            They can also include whitespace, for instance if you want to provide extra advice or examples.
        y (int): The second argument.

    Returns:
        Dict[int, int]: The return value. Please try to be as specific as possible when specifying input and return types. Consider adding an example if your function returns a dictionary/tuple/some other data type where the fields would otherwise have to be inferred by the client, like so::

        {"result1": 6, "result2": 9}


    Example:
        Usage examples should be included for shared, public interfaces. Otherwise, they are not required.
    """

    return {"result1": x * y, "result2": x ** y}

class ClassExample(object):
    """This is an example of how to document a class with docstrings.

    Classes should also have a one line summary, followed by additional description as appropriate.

    Attributes:
        a (str): Example of a public attribute of a class.

    Note:
        Notes, cautions, and examples may be used in classes just like they are in functions and modules.

    """
    
    def __init__(self):
        pass
