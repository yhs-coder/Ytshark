#include "dpi_list.h"

int main()
{
    // 1. 创建链表
    dpi_list* list = dpi_list_create();
    if (!list)
    {
        fprintf(stderr,"error in dpi_list_create\n");
        return -1;
    }

    // 2. 添加数据
    int* num1 = (int*)malloc(sizeof(int));
    int* num2 = (int*)malloc(sizeof(int));
    int* num3 = (int*)malloc(sizeof(int));
    int* num4 = (int*)malloc(sizeof(int));
    int* num5 = (int*)malloc(sizeof(int));

    *num1 = 10;
    *num2 = 20;
    *num3 = 30;
    *num4 = 40;
    *num5 = 50;

    dpi_list_append(list, num1);
    dpi_list_append(list, num2);
    dpi_list_append(list, num3);
    dpi_list_append(list, num4);
    dpi_list_append(list, num5);
    // 遍历链表
    dpi_list_node* begin = list->sentinal.next;
    while (begin != &list->sentinal)
    {
        int* tmp = (int*)(begin->data);
        printf("%d\n", *tmp);
        begin = begin->next;
    }
    printf("list size: %d\n",list->size);
    // 3.释放链表
    dpi_list_destroy(list);
    return 0;
}
