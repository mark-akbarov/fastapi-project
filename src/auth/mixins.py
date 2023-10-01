

class ToDictMixin:
    def to_dict(self, exclude=None):
        if exclude is None:
            exclude = []
        columns = [column for column in self.__table__.columns if column.name not in exclude]
        return {column.name: getattr(self, column.name) for column in columns}