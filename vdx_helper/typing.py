from typing import Union, List, Dict

AnyLiteral = Union[str, int, float, bool, complex]
Json = Union[List['Json'], Dict[AnyLiteral, 'Json'], AnyLiteral]
