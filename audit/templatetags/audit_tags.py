from django import template
from django.template.defaultfilters import stringfilter


@stringfilter
def truncatewords(value, arg):
    """Truncate text to specified number of words"""
    try:
        word_count = int(arg)
    except (ValueError, TypeError):
        return value
    
    words = value.split()
    if len(words) <= word_count:
        return value
    
    return ' '.join(words[:word_count]) + ('...' if len(words) > word_count else '')


@stringfilter  
def floatformat(value, arg):
    """Format float with specified precision"""
    try:
        precision = int(arg)
    except (ValueError, TypeError):
        return value
    
    try:
        return f"{float(value):.{precision}f}"
    except (ValueError, TypeError):
        return value


register = template.Library()
register.filter('truncatewords', truncatewords)
register.filter('floatformat', floatformat)
