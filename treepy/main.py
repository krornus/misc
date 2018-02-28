
class PostOrder:

    def __init__(self,node):
        self.stack = [node]
        self.root = node

    def __iter__(self):
        return self

    def next(self):

        if !self.stack:
            return

        while self.root:
             # Push root's right child and then root to stack
             if root.right is not None:
                stack.append(root.right)
             stack.append(root)

             # Set root as root's left child
             root = root.left

        # Pop an item from stack and set it as root
        root = stack.pop()

        # If the popped item has a right child and the
        # right child is not processed yet, then make sure
        # right child is processed before root
        if (root.right is not None and
            peek(stack) == root.right):
            stack.pop() # Remove right child from stack
            stack.append(root) # Push root back to stack
            root = root.right # change root so that the
                             # righ childis processed next

        # Else print root's data and set root as None
        else:
            ans.append(root.data)
            root = None



# so we do a thing with an unranked tree
# each node creates a new entry in the matrix
# square matrix?
class Node:

    def __init__(self, data, children):
        self.children = [children]
        self.data = data
        self.postorder = PostOrder(self)

    # An iterative function to do postorder traversal of a
    # given binary tree
    def postorder(self):

        # Run while first stack is not empty
        while len(s1) > 0:

            # Pop an item from s1 and append it to s2
            node = s1.pop()
            s2.append(node)

            # Push left and right children of removed item to s1
            if node.left is not None:
                s1.append(node.left)
            if node.right is not None :
                s1.append(node.right)

        # Print all eleements of second stack
        while(len(s2) > 0):
            node = s2.pop()
            print node.data,

root = Node("A", [
    Node("B", []),
    Node("C", []),
])
