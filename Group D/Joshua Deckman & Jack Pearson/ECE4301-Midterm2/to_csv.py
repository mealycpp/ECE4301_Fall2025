if __name__ == '__main__':
    max_points = None
    while max_points is None:
        try:
            max_points = int(input("Enter number of points to acquire: "))
        except ValueError:
            max_points = None

    source_file = input("Enter source file: ")
    csv_file = input("Enter csv file to which to store data: ")

    num_points = 0

    with open(csv_file, 'w') as new_csv_file:
        new_csv_file.write("X,Y\n")
        with open(source_file, 'rb') as rand_data:
            while num_points < max_points:
                next_bytes = rand_data.read(2)
                if not next_bytes:
                    break

                left_coord = next_bytes[0]
                right_coord = next_bytes[1]
                new_csv_file.write(f"{left_coord},{right_coord}\n")
                num_points += 1

    print(f"Saved {num_points} points.")
