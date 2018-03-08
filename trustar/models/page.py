# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library

# package imports
from .base import ModelBase

# external imports
import math


class Page(ModelBase):
    """
    This class models a page of items that would be found in the body of a response from an endpoint that uses
    pagination.

    :ivar items: The list of items of the page; i.e. a list of indicators, reports, etc.
    :ivar page_number: The number of the page out of all total pages, indexed from 0.  i.e. if there are
        4 total pages of size 25, then page 0 will contain the first 25 elements, page 1 will contain the next 25, etc.
    :ivar page_size: The size of the page that was request.  Note that, if this is the last page, then this might
        not equal len(items).  For instance, if pages of size 25 were requested, there are 107 total elements, and
        this is the last page, then page_size will be 25 even though the page only contains 7 elements.
    :ivar total_elements: The total number of elements on the server, e.g. the total number of elements across all
        pages.  Note that it is possible for this value to change between pages, since data can change between queries.
    """

    def __init__(self, items=None, page_number=None, page_size=None, total_elements=None):
        self.items = items
        self.page_number = page_number
        self.page_size = page_size
        self.total_elements = total_elements

    def get_total_pages(self):
        """
        :return: The total number of pages on the server.
        """

        if self.total_elements is None or self.page_size is None:
            return None

        return math.ceil(float(self.total_elements) / float(self.page_size))

    def has_more_pages(self):
        """
        :return: ``True`` if there are more pages available on the server.
        """

        total_pages = self.get_total_pages()
        if self.page_number is None or total_pages is None:
            return None

        return self.page_number + 1 < total_pages

    def __len__(self):
        return len(self.items)

    @staticmethod
    def from_dict(page, content_type=None):
        """
        Create a |Page| object from a dictionary.  This method is intended for internal use, to construct a
        |Page| object from the body of a response json from a paginated endpoint.

        :param page: The dictionary.
        :param content_type: The class that the contents should be deserialized into.
        :return: The resulting |Page| object.
        """

        result = Page(items=page['items'],
                      page_number=page['pageNumber'],
                      page_size=page['pageSize'],
                      total_elements=page['totalElements'])

        if content_type is not None:
            if not hasattr(content_type, 'from_dict'):
                raise Exception("content_type parameter must have a 'from_dict' method.")

            result.items = map(content_type.from_dict, result.items)

        return result

    def to_dict(self, remove_nones=False):
        """
        Creates a dictionary representation of the page.

        :param remove_nones: Whether ``None`` values should be filtered out of the dictionary.  Defaults to ``False``.
        :return: A dictionary representation of the page.
        """

        items = []

        # attempt to replace each item with its dictionary representation if possible
        for item in self.items:
            if hasattr(item, 'to_dict'):
                items.append(item.to_dict(remove_nones=remove_nones))
            else:
                items.append(item)

        return {
            'items': items,
            'pageNumber': self.page_number,
            'pageSize': self.page_size,
            'totalElements': self.total_elements
        }

    @staticmethod
    def get_page_generator(func, start_page=0, page_size=None):
        """
        Constructs a generator for retrieving pages from a paginated endpoint.  This method is intended for internal
        use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Page| object.
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :return: A |GeneratorWithLength| instance that can be used to generate each successive page.
        """

        def generator():

            # initialize starting values
            page_number = start_page
            more_pages = True

            # continuously request the next page as long as more pages exist
            while more_pages:

                # get next page
                page = func(page_number=page_number, page_size=page_size)

                yield page

                # determine whether more pages exist
                more_pages = page.has_more_pages()
                page_number += 1

        return generator()

    @classmethod
    def get_generator(cls, func=None, page_generator=None):
        """
        Gets a generator for retrieving all results from a paginated endpoint.  Pass exactly one of ``page_generator``
        or ``func``.  This method is intended for internal use.

        :param func: Should take parameters ``page_number`` and ``page_size`` and return the corresponding |Page|
            object.  If ``page_iterator`` is ``None``, this will be used to create one.
        :param page_generator: A generator to be used to generate each successive |Page|.
        :return: A |GeneratorWithLength| instance that can be used to generate each successive element.
        """

        # if page_iterator is None, use func to create one
        if page_generator is None:
            if func is None:
                raise Exception("To use 'get_iterator', must provide either a page iterator or a method.")
            else:
                page_generator = cls.get_page_generator(func)

        def iterable():
            # yield each item in the page one by one;
            # once it is out, generate the next page
            for page in page_generator:
                for item in page.items:
                    yield item

        return iterable()

    def __iter__(self):
        return self.items.__iter__()

    def __getitem__(self, item):
        return self.items[item]
